package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

func guardedItem(sequence uint32, poison bool) spool.Item {
	item := testItem(sequence, "guarded-fixture")
	item.Event.AgentReceivedAt = item.Event.ID.Timestamp
	item.CheckpointInvalidatedFields = []string{"enforcement"}
	raw := fmt.Sprintf(`audit(%d.000:%d): avc: denied { read } for pid=10 comm="httpd" path="/srv/guarded-%d" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0`, 100+sequence, sequence, sequence)
	if poison {
		raw = " "
	} // Locally nonempty bytes; server rejects decoded blank payload.
	item.Event.Records[0].Raw = []byte(raw)
	return item
}

func markedRejection(index int) protocol.ErrorResponse {
	return protocol.ErrorResponse{Error: protocol.ErrorBody{Code: "invalid_request", Phase: "pre_persistence", Message: "not used for decisions", Details: []protocol.ValidationDetail{{Path: fmt.Sprintf("events[%d].records[0].payload", index), Code: "required"}}}}
}

func TestSplitEligibleResponse(t *testing.T) {
	entries := []spool.Entry{{Item: guardedItem(1, false)}, {Item: guardedItem(2, false)}}
	valid := markedRejection(1)
	for _, tc := range []struct {
		name   string
		mutate func(*protocol.ErrorResponse)
		want   bool
	}{
		{"valid", func(r *protocol.ErrorResponse) {}, true},
		{"old server", func(r *protocol.ErrorResponse) { r.Error.Phase = "" }, false},
		{"unknown phase", func(r *protocol.ErrorResponse) { r.Error.Phase = "post_commit" }, false},
		{"wrong error", func(r *protocol.ErrorResponse) { r.Error.Code = "unauthorized" }, false},
		{"missing details", func(r *protocol.ErrorResponse) { r.Error.Details = nil }, false},
		{"unknown code", func(r *protocol.ErrorResponse) { r.Error.Details[0].Code = "future_code" }, false},
		{"conflict", func(r *protocol.ErrorResponse) { r.Error.Details[0].Code = "conflicting_duplicate" }, false},
		{"mixed shared", func(r *protocol.ErrorResponse) {
			r.Error.Details = append(r.Error.Details, protocol.ValidationDetail{Path: "boot_id", Code: "required"})
		}, false},
		{"human text irrelevant", func(r *protocol.ErrorResponse) { r.Error.Message = "permission denied; split all admin events" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := markedRejection(1)
			tc.mutate(&response)
			data, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if _, got := splitEligibleResponse(data, entries); got != tc.want {
				t.Fatalf("eligible=%v", got)
			}
		})
	}
	for _, path := range []string{"host_id", "checkpoint_invalidated_fields", "events", "random.path", "events[-1].category", "events[+1].category", "events[01].category", "events[2].category", "events[999999999999999999999999].category", "events[1].records[1].payload", "events[1].records[0].future", "events[1].category.trailing", "events[1]oops"} {
		response := markedRejection(1)
		response.Error.Details[0].Path = path
		data, _ := json.Marshal(response)
		if _, ok := splitEligibleResponse(data, entries); ok {
			t.Fatalf("accepted path %q", path)
		}
	}
	for _, path := range []string{"events[0]", "events[1].audit_event.sequence", "events[1].records[0]", "events[1].category"} {
		response := markedRejection(1)
		response.Error.Details[0].Path = path
		data, _ := json.Marshal(response)
		if _, ok := splitEligibleResponse(data, entries); !ok {
			t.Fatalf("refused %q", path)
		}
	}
	for _, data := range [][]byte{[]byte("{"), []byte("null"), []byte(`{"error":{"phase":true}}`), bytes.Repeat([]byte(" "), maxValidationResponseBytes+1)} {
		if _, ok := splitEligibleResponse(data, entries); ok {
			t.Fatal("accepted malformed/oversized body")
		}
	}
	data, _ := json.Marshal(valid)
	data = append(data, []byte("{}")...)
	if _, ok := splitEligibleResponse(data, entries); ok {
		t.Fatal("accepted trailing JSON")
	}
}

func TestNonBoundaryCohort(t *testing.T) {
	for _, typ := range []auparse.AuditMessageType{auparse.AUDIT_AVC, auparse.AUDIT_USER_AVC, auparse.AUDIT_SYSCALL, auparse.AUDIT_PATH, auparse.AUDIT_AVC_PATH, auparse.AUDIT_PROCTITLE, auparse.AUDIT_EXECVE, auparse.AUDIT_CWD, auparse.AUDIT_EOE, auparse.AUDIT_SELINUX_ERR, auparse.AUDIT_MAC_POLICY_LOAD, auparse.AUDIT_MAC_CONFIG_CHANGE, auparse.AUDIT_MAC_STATUS, auparse.AUDIT_USER_MAC_CONFIG_CHANGE, auparse.AUDIT_SECCOMP, 65500} {
		item := guardedItem(1, false)
		item.Event.Records[0].Type = typ
		item.Event.Records[0].TypeName = typ.String()
		want := !audit.BoundaryCapableRecordType(typ) && typ != auparse.AUDIT_SECCOMP && typ != 65500
		if got := nonBoundaryCohort([]spool.Entry{{Item: item}}); got != want {
			t.Fatalf("type=%s got=%v", typ, got)
		}
	}
	item := guardedItem(1, false)
	item.Event.Records[0].TypeName = "MAC_STATUS"
	if nonBoundaryCohort([]spool.Entry{{Item: item}}) {
		t.Fatal("contradictory name")
	}
	item = guardedItem(1, false)
	item.Event.Category = audit.CategorySELinuxAdministrative
	if nonBoundaryCohort([]spool.Entry{{Item: item}}) {
		t.Fatal("administrative category")
	}
	item.Event.Category = audit.CategoryAVC
	item.Event.Records = nil
	if nonBoundaryCohort([]spool.Entry{{Item: item}}) || nonBoundaryCohort(nil) {
		t.Fatal("empty evidence")
	}
}

type guardedLedger struct {
	mu           sync.Mutex
	batches      []int
	accepted     map[uint32]string
	observations []uint32
	rejected     int
	legacy       bool
	interrupt    bool
	interrupted  bool
	cancel       context.CancelFunc
	loseResponse bool
}

func (s *guardedLedger) serve(t testing.TB, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/expected-context-observations" {
		var observation protocol.ExpectedContextObservationRequest
		if err := json.NewDecoder(r.Body).Decode(&observation); err != nil {
			t.Error(err)
		}
		if _, ok := s.accepted[observation.AuditEvent.Sequence]; !ok {
			w.WriteHeader(404)
			return
		}
		s.observations = append(s.observations, observation.AuditEvent.Sequence)
		w.WriteHeader(202)
		return
	}
	var request protocol.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Error(err)
		w.WriteHeader(400)
		return
	}
	s.batches = append(s.batches, len(request.Events))
	if request.HostID != "guarded-fixture" || request.BootID != "boot" || request.HostObservedAt == nil || !request.HostObservedAt.Equal(time.Unix(99, 0)) || !slices.Equal(request.CheckpointInvalidatedFields, []string{"enforcement"}) {
		t.Error("shared metadata changed")
	}
	if s.interrupt && !s.interrupted && len(s.accepted) >= 50 {
		s.interrupted = true
		if s.cancel != nil {
			s.cancel()
			return
		}
		w.WriteHeader(500)
		return
	}
	for index, event := range request.Events {
		for position, record := range event.Records {
			if string(record.Raw) == " " {
				s.rejected++
				rejection := markedRejection(index)
				rejection.Error.Details[0].Path = fmt.Sprintf("events[%d].records[%d].payload", index, position)
				if s.legacy {
					rejection.Error.Phase = ""
				}
				w.WriteHeader(422)
				_ = json.NewEncoder(w).Encode(rejection)
				return
			}
		}
	}
	for _, event := range request.Events {
		digest := audit.EvidenceDigest(event)
		if old, ok := s.accepted[event.ID.Sequence]; ok && old != digest {
			t.Error("replay evidence changed")
		}
		s.accepted[event.ID.Sequence] = digest
	}
	if s.loseResponse && !s.interrupted && len(s.accepted) >= 50 {
		s.interrupted = true
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
		return
	}
	w.WriteHeader(202)
}

func guardedStore(t testing.TB, count int, poisons []uint32) (*spool.Spool, string, []spool.Item) {
	t.Helper()
	root := t.TempDir()
	store, err := spool.New(root, spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var items []spool.Item
	for sequence := uint32(1); sequence <= uint32(count); sequence++ {
		item := guardedItem(sequence, slices.Contains(poisons, sequence))
		items = append(items, item)
		if err := store.Put(item); err != nil {
			t.Fatal(err)
		}
	}
	return store, root, items
}

func spoolFootprint(t *testing.T, root string) (int, int, int64) {
	t.Helper()
	var pending, blocked int
	var size int64
	for _, directory := range []string{"pending", "blocked"} {
		files, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			info, err := file.Info()
			if err != nil {
				t.Fatal(err)
			}
			size += info.Size()
			if strings.HasSuffix(file.Name(), ".json") {
				if directory == "pending" {
					pending++
				} else {
					blocked++
				}
			}
		}
	}
	return pending, blocked, size
}

func quietClient(endpoint string) Client {
	return Client{Endpoint: endpoint, IngestionKey: "test-key", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestGuardedPoisonConvergence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		poisons []uint32
		legacy  bool
	}{
		{"healthy", nil, false},
		{"one", []uint32{100}, false}, {"beginning_end", []uint32{1, 100}, false}, {"adjacent_middle", []uint32{50, 51}, false}, {"opposite_halves", []uint32{25, 75}, false}, {"old_server", []uint32{100}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, root, items := guardedStore(t, 100, tc.poisons)
			_, _, before := spoolFootprint(t, root)
			scan, err := store.Pending()
			if err != nil {
				t.Fatal(err)
			}
			originals := map[string][]byte{}
			for _, entry := range scan.Entries {
				data, err := os.ReadFile(filepath.Join(root, "pending", entry.ID+".json"))
				if err != nil {
					t.Fatal(err)
				}
				originals[entry.ID] = data
			}
			ledger := &guardedLedger{accepted: map[uint32]string{}, legacy: tc.legacy}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(t, w, r) }))
			defer server.Close()
			result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
			pending, blocked, after := spoolFootprint(t, root)
			ledger.mu.Lock()
			accepted, rejected, batches := len(ledger.accepted), ledger.rejected, slices.Clone(ledger.batches)
			ledger.mu.Unlock()
			if tc.legacy {
				if _, ok := errors.AsType[*PermanentError](err); !ok || blocked != 100 || accepted != 0 || len(batches) != 1 || result.GuardedSplits != 0 {
					t.Fatalf("legacy result=%+v err=%v", result, err)
				}
			} else {
				if err != nil || pending != 0 || blocked != len(tc.poisons) || accepted != 100-len(tc.poisons) || result.Delivered != accepted || result.IsolatedRejections != blocked {
					t.Fatalf("result=%+v accepted=%d err=%v", result, accepted, err)
				}
				if len(tc.poisons) == 1 && len(batches) > 15 {
					t.Fatalf("one-poison attempts=%d", len(batches))
				}
				for id, data := range originals {
					blockedData, err := os.ReadFile(filepath.Join(root, "blocked", id+".json"))
					if os.IsNotExist(err) {
						continue
					}
					if err != nil || !bytes.Equal(data, blockedData) {
						t.Fatal("blocked evidence changed")
					}
					var reason protocol.ErrorBody
					data, err = os.ReadFile(filepath.Join(root, "blocked", id+".json.rejection"))
					if err != nil || json.Unmarshal(data, &reason) != nil || reason.Phase != "pre_persistence" || len(reason.Details) == 0 || reason.Message != "" {
						t.Fatalf("durable rejection missing: %s %v", data, err)
					}
				}
				// Lost-success/reordered replay is keyed independently of transport grouping.
				for _, item := range items {
					if !slices.Contains(tc.poisons, item.Event.ID.Sequence) {
						if err := store.Put(item); err != nil {
							t.Fatal(err)
						}
					}
				}
				replay, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
				if err != nil || replay.Delivered != accepted {
					t.Fatalf("replay=%+v err=%v", replay, err)
				}
				ledger.mu.Lock()
				if len(ledger.accepted) != accepted {
					t.Error("duplicate semantics")
				}
				ledger.mu.Unlock()
			}
			t.Logf("attempts=%d sizes=%v accepted=%d rejected_requests=%d pending=%d blocked=%d bytes=%d -> %d", len(batches), batches, accepted, rejected, pending, blocked, before, after)
		})
	}
}

func TestGuardedAllPoisonTerminates(t *testing.T) {
	var poisons []uint32
	for sequence := uint32(1); sequence <= 100; sequence++ {
		poisons = append(poisons, sequence)
	}
	store, root, _ := guardedStore(t, 100, poisons)
	ledger := &guardedLedger{accepted: map[uint32]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(t, w, r) }))
	defer server.Close()
	result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
	pending, blocked, _ := spoolFootprint(t, root)
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err != nil || pending != 0 || blocked != 100 || result.IsolatedRejections != 100 || len(ledger.batches) != 199 || len(ledger.accepted) != 0 {
		t.Fatalf("result=%+v attempts=%d err=%v", result, len(ledger.batches), err)
	}
	t.Logf("all-poison attempts=%d guarded_splits=%d", len(ledger.batches), result.GuardedSplits)
}

func TestGuardedAdministrativeAndUnknownRefusal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		typ         auparse.AuditMessageType
		category    audit.Category
		adminPoison bool
	}{
		{"policy_load", auparse.AUDIT_MAC_POLICY_LOAD, audit.CategorySELinuxAdministrative, true},
		{"runtime_boolean", auparse.AUDIT_MAC_CONFIG_CHANGE, audit.CategorySELinuxAdministrative, true},
		{"mac_status", auparse.AUDIT_MAC_STATUS, audit.CategorySELinuxAdministrative, true},
		{"port", auparse.AUDIT_USER_MAC_CONFIG_CHANGE, audit.CategorySELinuxAdministrative, true},
		{"fcontext", auparse.AUDIT_USER_MAC_CONFIG_CHANGE, audit.CategorySELinuxAdministrative, true},
		{"valid_admin_bad_avc", auparse.AUDIT_MAC_STATUS, audit.CategorySELinuxAdministrative, false},
		{"mixed_avc_status", auparse.AUDIT_MAC_STATUS, audit.CategoryAVC, false},
		{"unknown", 65500, audit.CategoryAVC, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store, err := spool.New(root, spool.Config{})
			if err != nil {
				t.Fatal(err)
			}
			first := guardedItem(1, tc.adminPoison)
			first.Event.Category = tc.category
			first.Event.Records[0].Type = tc.typ
			first.Event.Records[0].TypeName = tc.typ.String()
			if tc.adminPoison {
				payload := "res=1"
				switch tc.name {
				case "runtime_boolean":
					payload = "bool=httpd_can_network_connect val=0 old_val=1"
				case "mac_status":
					payload = "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1"
				case "port":
					payload = "msg='resrc=port op=add proto=6 lport=12345 tcontext=system_u:object_r:http_port_t:s0 res=success'"
				case "fcontext":
					payload = `msg='resrc=fcontext op=add tglob="/srv/guarded" ftype=any tcontext=system_u:object_r:httpd_sys_content_t: res=success'`
				}
				first.Event.Records[0].Raw = []byte("audit(101.000:1): " + payload)
				first.Event.Records = append(first.Event.Records, audit.Record{Position: 1, Type: auparse.AUDIT_SYSCALL, TypeName: "SYSCALL", Timestamp: first.Event.ID.Timestamp, Sequence: 1, Raw: []byte(" ")})
			}
			if !tc.adminPoison && tc.typ == auparse.AUDIT_MAC_STATUS {
				first.Event.Records[0].Raw = []byte("audit(101.000:1): enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1")
			}
			for _, item := range []spool.Item{first, guardedItem(2, true), guardedItem(3, false)} {
				if err := store.Put(item); err != nil {
					t.Fatal(err)
				}
			}
			ledger := &guardedLedger{accepted: map[uint32]string{}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(t, w, r) }))
			defer server.Close()
			result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			if _, ok := errors.AsType[*PermanentError](err); !ok || result.Blocked != 3 || result.GuardedSplits != 0 || len(ledger.batches) != 1 {
				t.Fatalf("unsafe split result=%+v err=%v", result, err)
			}
		})
	}
}

func TestGuardedRestartAndUncertainResponse(t *testing.T) {
	for _, mode := range []string{"500", "cancellation", "lost_success"} {
		t.Run(mode, func(t *testing.T) {
			store, root, _ := guardedStore(t, 100, []uint32{100})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ledger := &guardedLedger{accepted: map[uint32]string{}, interrupt: mode != "lost_success", loseResponse: mode == "lost_success"}
			if mode == "cancellation" {
				ledger.cancel = cancel
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(t, w, r) }))
			defer server.Close()
			result, err := quietClient(server.URL+"/events").SendPending(ctx, store)
			pending, blocked, _ := spoolFootprint(t, root)
			wantPending := 50
			if mode == "lost_success" {
				wantPending = 100
			}
			if err == nil || blocked != 0 || pending != wantPending || result.Pending != wantPending {
				t.Fatalf("interruption result=%+v pending=%d err=%v", result, pending, err)
			}
			ledger.mu.Lock()
			ledger.interrupt = false
			ledger.loseResponse = false
			ledger.cancel = nil
			ledger.mu.Unlock()
			reopened, err := spool.New(root, spool.Config{})
			if err != nil {
				t.Fatal(err)
			}
			result, err = quietClient(server.URL+"/events").SendPending(t.Context(), reopened)
			pending, blocked, _ = spoolFootprint(t, root)
			ledger.mu.Lock()
			defer ledger.mu.Unlock()
			if err != nil || pending != 0 || blocked != 1 || len(ledger.accepted) != 99 {
				t.Fatalf("restart=%+v accepted=%d err=%v", result, len(ledger.accepted), err)
			}
		})
	}
}

func TestGuardedOptionalObservations(t *testing.T) {
	store, _, items := guardedStore(t, 100, []uint32{100})
	queueGuardedObservations(t, store, items)
	ledger := &guardedLedger{accepted: map[uint32]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(t, w, r) }))
	defer server.Close()
	result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err != nil || result.Delivered != 99 || result.ExpectedContextDelivered != 1 || result.ExpectedContextBlocked != 1 || !slices.Equal(ledger.observations, []uint32{1}) {
		t.Fatalf("optional=%+v err=%v", result, err)
	}
}

func queueGuardedObservations(t testing.TB, store *spool.Spool, items []spool.Item) {
	t.Helper()
	for _, sequence := range []uint32{1, 100} {
		item := items[sequence-1]
		request := protocol.ExpectedContextObservationRequest{SchemaVersion: protocol.ExpectedContextSchemaVersion, Agent: item.Agent, HostID: item.HostID, BootID: item.BootID, HostObservedAt: item.HostObservedAt, AuditEvent: protocol.AuditEventReference{Timestamp: item.Event.ID.Timestamp, Sequence: sequence}, Observation: protocol.ExpectedContextObservation{Path: fmt.Sprintf("/srv/guarded-%d", sequence), ObjectClass: "file", FileType: "file", ExpectedContext: "system_u:object_r:var_t:s0", ObservedAt: item.Event.ID.Timestamp.Add(time.Second), Resolver: "matchpathcon", Status: "resolved"}}
		if err := store.PutExpectedContextObservation(request); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkNonBoundaryCohort100(b *testing.B) {
	entries := make([]spool.Entry, 100)
	for index := range entries {
		entries[index].Item = guardedItem(uint32(index+1), false)
		item := &entries[index].Item
		for _, typ := range []auparse.AuditMessageType{auparse.AUDIT_SYSCALL, auparse.AUDIT_PATH, auparse.AUDIT_PROCTITLE, auparse.AUDIT_EOE} {
			item.Event.Records = append(item.Event.Records, audit.Record{Type: typ, TypeName: typ.String()})
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		if !nonBoundaryCohort(entries) {
			b.Fatal("not proven")
		}
	}
}

func TestGuardedNonEligibleHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		mutate    func(*protocol.ErrorResponse)
		truncated bool
	}{
		{"401", 401, func(r *protocol.ErrorResponse) {}, false},
		{"403", 403, func(r *protocol.ErrorResponse) {}, false},
		{"old_server", 422, func(r *protocol.ErrorResponse) { r.Error.Phase = "" }, false},
		{"integrity", 422, func(r *protocol.ErrorResponse) { r.Error.Details[0].Code = "conflicting_duplicate" }, false},
		{"shared", 422, func(r *protocol.ErrorResponse) { r.Error.Details[0].Path = "host_id" }, false},
		{"unknown_code", 422, func(r *protocol.ErrorResponse) { r.Error.Details[0].Code = "future_code" }, false},
		{"500_with_marker", 500, func(r *protocol.ErrorResponse) {}, false},
		{"408", 408, func(r *protocol.ErrorResponse) {}, false},
		{"429", 429, func(r *protocol.ErrorResponse) {}, false},
		{"truncated_body", 422, func(r *protocol.ErrorResponse) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, root, _ := guardedStore(t, 3, []uint32{2})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				response := markedRejection(1)
				tc.mutate(&response)
				if tc.truncated {
					w.Header().Set("Content-Length", "10000")
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
			pending, blocked, _ := spoolFootprint(t, root)
			if err == nil || requests.Load() != 1 || result.GuardedSplits != 0 {
				t.Fatalf("result=%+v requests=%d err=%v", result, requests.Load(), err)
			}
			transient := tc.status >= 500 || tc.status == 408 || tc.status == 429 || tc.truncated
			if transient {
				if pending != 3 || blocked != 0 {
					t.Fatal("uncertain events not pending")
				}
			} else if pending != 0 || blocked != 3 {
				t.Fatal("atomic quarantine changed")
			}
		})
	}
}

func TestGuardedChildMustProveEligibility(t *testing.T) {
	store, root, _ := guardedStore(t, 100, []uint32{100})
	ledger := &guardedLedger{accepted: map[uint32]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var request protocol.IngestRequest
		if json.Unmarshal(data, &request) != nil {
			t.Error("bad request")
			return
		}
		if len(request.Events) == 50 && request.Events[0].ID.Sequence == 1 {
			response := markedRejection(0)
			response.Error.Details[0].Code = "future_code"
			w.WriteHeader(422)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		ledger.serve(t, w, r)
	}))
	defer server.Close()
	result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
	pending, blocked, _ := spoolFootprint(t, root)
	if _, ok := errors.AsType[*PermanentError](err); !ok || pending != 0 || blocked != 51 || result.Delivered != 49 || result.IsolatedRejections != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestGuardedOriginalProofSurvives413(t *testing.T) {
	for _, boundary := range []uint32{1, 4} {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			root := t.TempDir()
			store, err := spool.New(root, spool.Config{})
			if err != nil {
				t.Fatal(err)
			}
			for sequence := uint32(1); sequence <= 4; sequence++ {
				item := guardedItem(sequence, true)
				if sequence == boundary {
					item.Event.Records[0].Type = auparse.AUDIT_MAC_STATUS
					item.Event.Records[0].TypeName = "MAC_STATUS"
				}
				if err := store.Put(item); err != nil {
					t.Fatal(err)
				}
			}
			ledger := &guardedLedger{accepted: map[uint32]string{}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				var request protocol.IngestRequest
				_ = json.Unmarshal(data, &request)
				if len(request.Events) > 2 {
					w.WriteHeader(413)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(data))
				ledger.serve(t, w, r)
			}))
			defer server.Close()
			result, err := quietClient(server.URL+"/events").SendPending(t.Context(), store)
			if _, ok := errors.AsType[*PermanentError](err); !ok || result.Blocked != 4 || result.GuardedSplits != 0 {
				t.Fatalf("descendant lost original proof: %+v %v", result, err)
			}
		})
	}
}

func BenchmarkGuardedPoison100(b *testing.B) {
	ledger := &guardedLedger{accepted: map[uint32]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ledger.serve(b, w, r) }))
	defer server.Close()
	client := quietClient(server.URL + "/events")
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		store, _, _ := guardedStore(b, 100, []uint32{100})
		ledger.mu.Lock()
		clear(ledger.accepted)
		ledger.batches = nil
		ledger.rejected = 0
		ledger.mu.Unlock()
		b.StartTimer()
		result, err := client.SendPending(b.Context(), store)
		if err != nil || result.Delivered != 99 || result.Blocked != 1 {
			b.Fatalf("result=%+v err=%v", result, err)
		}
	}
}

// Opt-in only against a disposable Rails test database/loopback endpoint.
func TestGuardedRealServerContract(t *testing.T) {
	endpoint := os.Getenv("SECENTRAL_GUARDED_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set loopback disposable Rails test endpoint")
	}
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("test endpoint must be loopback")
	}
	store, root, items := guardedStore(t, 100, []uint32{100})
	queueGuardedObservations(t, store, items)
	client := quietClient(endpoint)
	client.IngestionKey = "guarded-acceptance-key"
	result, err := client.SendPending(t.Context(), store)
	pending, blocked, _ := spoolFootprint(t, root)
	if err != nil || pending != 0 || blocked != 1 || result.Delivered != 99 || result.IsolatedRejections != 1 || result.ExpectedContextDelivered != 1 || result.ExpectedContextBlocked != 1 {
		t.Fatalf("real server=%+v err=%v", result, err)
	}
	for _, item := range items[:99] {
		if err := store.Put(item); err != nil {
			t.Fatal(err)
		}
	}
	replay, err := client.SendPending(t.Context(), store)
	if err != nil || replay.Delivered != 99 {
		t.Fatalf("real replay=%+v err=%v", replay, err)
	}
	t.Logf("real server accepted=%d blocked=%d splits=%d, replay accepted=%d", result.Delivered, result.Blocked, result.GuardedSplits, replay.Delivered)
}
