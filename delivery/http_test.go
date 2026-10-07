package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/secentral/agent/metadata"
	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

func TestSendPendingAcknowledges202(t *testing.T) {
	store, item := testSpool(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || bytes.Contains(body, []byte("secret")) {
			t.Fatalf("ingestion key appeared in payload: %v", err)
		}
		var request protocol.IngestRequest
		if err := json.Unmarshal(body, &request); err != nil || len(request.Events) != 1 {
			t.Fatalf("request = %#v, err=%v", request, err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Pending != 0 || result.Delivered != 1 {
		t.Fatalf("pending = %d, delivered = %d", result.Pending, result.Delivered)
	}
	if pending, _ := store.Pending(); len(pending.Entries) != 0 {
		t.Fatalf("pending entries after acknowledgement = %d", len(pending.Entries))
	}
	_ = item
}

func TestExpectedContextObservationWaitsForAVCAndSurvivesServerInterruption(t *testing.T) {
	store, item := testSpool(t)
	timestamp := item.Event.ID.Timestamp
	observation := protocol.ExpectedContextObservationRequest{
		SchemaVersion: protocol.ExpectedContextSchemaVersion,
		Agent:         item.Agent,
		HostID:        item.HostID,
		BootID:        item.BootID,
		AuditEvent:    protocol.AuditEventReference{Timestamp: timestamp, Sequence: item.Event.ID.Sequence},
		Observation: protocol.ExpectedContextObservation{
			Path: "/srv/file", ObjectClass: "file", FileType: "file",
			ExpectedContext: "system_u:object_r:expected_t:s0", ObservedAt: timestamp.Add(time.Second),
			Resolver: "matchpathcon", Status: "resolved",
		},
	}
	if err := store.PutExpectedContextObservation(observation); err != nil {
		t.Fatal(err)
	}

	var online atomic.Bool
	var order []string
	var orderMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online.Load() {
			http.Error(w, "offline", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/events":
			orderMu.Lock()
			order = append(order, "event")
		case "/expected-context-observations":
			orderMu.Lock()
			order = append(order, "observation")
			orderMu.Unlock()
			var got protocol.ExpectedContextObservationRequest
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got.Observation.Path != observation.Observation.Path {
				t.Fatalf("observation request = %#v, err=%v", got, err)
			}
		default:
			t.Fatalf("unexpected endpoint %s", r.URL.Path)
		}
		if r.URL.Path == "/events" {
			orderMu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client := Client{Endpoint: server.URL + "/events", IngestionKey: "secret"}

	result, err := client.SendPending(t.Context(), store)
	if err == nil || result.Pending != 1 {
		t.Fatalf("offline result = %#v, err=%v", result, err)
	}
	if pending, _ := store.ExpectedContextPending(); len(pending.Entries) != 1 {
		t.Fatalf("offline observation entries = %d", len(pending.Entries))
	}

	order = nil
	online.Store(true)
	result, err = client.SendPending(t.Context(), store)
	if err != nil || result.Delivered != 1 || result.ExpectedContextDelivered != 1 {
		t.Fatalf("reconnected result = %#v, err=%v", result, err)
	}
	orderMu.Lock()
	gotOrder := append([]string(nil), order...)
	orderMu.Unlock()
	if len(gotOrder) != 2 || gotOrder[0] != "event" || gotOrder[1] != "observation" {
		t.Fatalf("delivery order = %#v", gotOrder)
	}
	if pending, _ := store.ExpectedContextPending(); len(pending.Entries) != 0 {
		t.Fatalf("observation remains queued = %d", len(pending.Entries))
	}
}

func TestSendHeartbeatPostsMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/heartbeat" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var request protocol.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Host.ID != "host" || request.Agent.Version != "test" {
			t.Fatalf("request = %#v, err=%v", request, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"policy_artifact_required":true,"policy_identity":"sha256:abc"}`)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL + "/events", IngestionKey: "secret"}).SendHeartbeat(t.Context(), metadata.HostMetadata{ID: "host"}, time.Unix(99, 0).UTC(), "test")
	if err != nil || !result.PolicyArtifactRequired || result.PolicyIdentity != "sha256:abc" {
		t.Fatal(err)
	}
}

func TestUploadPolicyArtifactUsesAuthenticatedBinaryEndpoint(t *testing.T) {
	artifact := []byte("exact policy bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, artifact) || r.Method != http.MethodPut || r.URL.Path != "/policy-artifacts/sha256:abc" {
			t.Fatalf("request = %s %s, body=%q, err=%v", r.Method, r.URL.Path, body, err)
		}
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-SECentral-Host-ID") != "host" || r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("headers = %#v", r.Header)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	if err := (Client{Endpoint: server.URL + "/events", IngestionKey: "secret"}).UploadPolicyArtifact(t.Context(), "host", "sha256:abc", artifact); err != nil {
		t.Fatal(err)
	}
}

func TestSendPendingBlocksPermanentFailure(t *testing.T) {
	store, _ := testSpool(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "invalid", http.StatusUnprocessableEntity) }))
	defer server.Close()

	_, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if _, ok := err.(*PermanentError); !ok {
		t.Fatalf("error = %T %v", err, err)
	}
	if pending, _ := store.Pending(); len(pending.Entries) != 0 {
		t.Fatalf("pending entries after block = %d", len(pending.Entries))
	}
}

func TestSendPendingKeepsTemporaryFailureQueued(t *testing.T) {
	store, _ := testSpool(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "retry", http.StatusBadGateway) }))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err == nil {
		t.Fatal("expected temporary failure")
	}
	if result.Pending != 1 {
		t.Fatalf("pending = %d", result.Pending)
	}
	if pending, _ := store.Pending(); len(pending.Entries) != 1 {
		t.Fatalf("pending entries after temporary failure = %d", len(pending.Entries))
	}
}

func TestSendPendingDeliversCompatibleSubsets(t *testing.T) {
	store, _ := testSpool(t)
	item := testItem(2, "host")
	item.HostID = "different"
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(testItem(3, "host")); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 3 || requests.Load() != 2 {
		t.Fatalf("result = %#v, requests = %d, err = %v", result, requests.Load(), err)
	}
}

func TestSendPendingSeparatesHostObservationTimes(t *testing.T) {
	store, _ := testSpool(t)
	item := testItem(2, "host")
	observedAt := item.HostObservedAt.Add(time.Minute)
	item.HostObservedAt = &observedAt
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 2 || requests.Load() != 2 {
		t.Fatalf("result = %#v, requests = %d, err = %v", result, requests.Load(), err)
	}
}

func TestSendPendingSeparatesAndPreservesCheckpointTrust(t *testing.T) {
	store, _ := testSpool(t)
	item := testItem(2, "host")
	item.CheckpointInvalidatedFields = []string{"booleans", "enforcement", "file_context_mappings", "policy_identity", "ports"}
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	var requests, masked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocol.IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		requests.Add(1)
		if len(request.Events) != 1 || request.HostObservedAt == nil {
			t.Errorf("incompatible checkpoint trust was combined: %#v", request)
		}
		if strings.Join(request.CheckpointInvalidatedFields, ",") == "booleans,enforcement,file_context_mappings,policy_identity,ports" {
			masked.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 2 || requests.Load() != 2 || masked.Load() != 1 {
		t.Fatalf("result=%#v requests=%d masked=%d err=%v", result, requests.Load(), masked.Load(), err)
	}
}

func TestSendPendingSplits413UntilSingleEvents(t *testing.T) {
	store, _ := testSpool(t)
	for sequence := uint32(2); sequence <= 3; sequence++ {
		if err := store.Put(testItem(sequence, "host")); err != nil {
			t.Fatal(err)
		}
	}
	var largest atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocol.IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if int32(len(request.Events)) > largest.Load() {
			largest.Store(int32(len(request.Events)))
		}
		if len(request.Events) > 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 3 || largest.Load() != 3 {
		t.Fatalf("result = %#v, largest = %d, err = %v", result, largest.Load(), err)
	}
}

func TestSendPendingBlocksOnlySingleEventAfter413(t *testing.T) {
	store, _ := testSpool(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if _, ok := err.(*PermanentError); !ok || result.Blocked != 1 {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if pending, _ := store.Pending(); len(pending.Entries) != 0 {
		t.Fatalf("pending entries after 413 = %d", len(pending.Entries))
	}
}

func TestSendPendingHonorsBatchLimit(t *testing.T) {
	store, _ := testSpool(t)
	for sequence := uint32(2); sequence <= 3; sequence++ {
		if err := store.Put(testItem(sequence, "host")); err != nil {
			t.Fatal(err)
		}
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocol.IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Events) > 2 {
			t.Fatalf("batch size = %d", len(request.Events))
		}
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret", MaxBatchEvents: 2}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 3 || requests.Load() != 2 {
		t.Fatalf("result = %#v, requests = %d, err = %v", result, requests.Load(), err)
	}
}

func TestSendPendingDeliversHealthyEntriesWithDiagnostics(t *testing.T) {
	root := t.TempDir()
	store, err := spool.New(root, spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(testItem(1, "host")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pending", "corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer server.Close()

	result, err := (Client{Endpoint: server.URL, IngestionKey: "secret"}).SendPending(t.Context(), store)
	if err != nil || result.Delivered != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestPoisonEventBlastRadiusAndLaterProgress(t *testing.T) {
	for _, mode := range []string{"permanent_422", "transient_500", "locally_invalid"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			store, err := spool.New(root, spool.Config{})
			if err != nil {
				t.Fatal(err)
			}
			for sequence := uint32(1); sequence <= 101; sequence++ {
				item := testItem(sequence, "host")
				item.Event.AgentReceivedAt = item.Event.ID.Timestamp
				if sequence == 1 {
					// Locally valid protocol metadata, but server category validation requires AVC.
					item.Event.Records[0].Type = auparse.AUDIT_SYSCALL
					item.Event.Records[0].TypeName = "SYSCALL"
					if mode == "locally_invalid" {
						item.Event.Records[0].Position = 99
					}
				}
				if err := store.Put(item); err != nil {
					t.Fatal(err)
				}
			}
			spoolBytes := func() int64 {
				var total int64
				for _, directory := range []string{"pending", "blocked"} {
					entries, err := os.ReadDir(filepath.Join(root, directory))
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						info, err := entry.Info()
						if err != nil {
							t.Fatal(err)
						}
						total += info.Size()
					}
				}
				return total
			}
			initialBytes := spoolBytes()
			if mode == "permanent_422" {
				for _, sequence := range []uint32{1, 101} {
					item := testItem(sequence, "host")
					observation := protocol.ExpectedContextObservationRequest{
						SchemaVersion: protocol.ExpectedContextSchemaVersion, Agent: item.Agent, HostID: item.HostID, BootID: item.BootID,
						AuditEvent:  protocol.AuditEventReference{Timestamp: item.Event.ID.Timestamp, Sequence: sequence},
						Observation: protocol.ExpectedContextObservation{Path: "/srv/probe", ObjectClass: "file", FileType: "file", Resolver: "matchpathcon", Status: "resolved", ExpectedContext: "system_u:object_r:var_t:s0", ObservedAt: item.Event.ID.Timestamp.Add(time.Second)},
					}
					if err := store.PutExpectedContextObservation(observation); err != nil {
						t.Fatal(err)
					}
				}
			}
			var mu sync.Mutex
			var requestSizes []int
			var acceptedIDs []uint32
			snapshot := func() ([]int, []uint32) {
				mu.Lock()
				defer mu.Unlock()
				return slices.Clone(requestSizes), slices.Clone(acceptedIDs)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/expected-context-observations" {
					var observation protocol.ExpectedContextObservationRequest
					if err := json.NewDecoder(r.Body).Decode(&observation); err != nil {
						t.Error(err)
					}
					if observation.AuditEvent.Sequence == 1 {
						w.WriteHeader(http.StatusNotFound)
					} else {
						w.WriteHeader(http.StatusAccepted)
					}
					return
				}
				var request protocol.IngestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requestSizes = append(requestSizes, len(request.Events))
				for _, event := range request.Events {
					if event.ID.Sequence == 1 {
						status := http.StatusUnprocessableEntity
						if mode == "transient_500" {
							status = http.StatusInternalServerError
						}
						w.WriteHeader(status)
						return
					}
				}
				for _, event := range request.Events {
					acceptedIDs = append(acceptedIDs, event.ID.Sequence)
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			client := Client{Endpoint: server.URL, IngestionKey: "secret"}
			start := time.Now()
			result, err := client.SendPending(t.Context(), store)
			sizes, accepted := snapshot()
			switch mode {
			case "permanent_422":
				if _, ok := errors.AsType[*PermanentError](err); !ok || result.Blocked != 100 || result.Delivered != 1 || len(accepted) != 1 || accepted[0] != 101 {
					t.Fatalf("permanent result=%#v accepted=%v err=%v", result, accepted, err)
				}
				if !slices.Equal(sizes, []int{100, 1}) {
					t.Fatalf("permanent requests=%v", sizes)
				}
				observations, err := store.ExpectedContextPending()
				if err != nil || len(observations.Entries) != 2 {
					t.Fatalf("optional observations did not wait after primary rejection: %#v, %v", observations, err)
				}
			case "transient_500":
				for range 2 {
					if err == nil || result.Blocked != 0 || result.Delivered != 0 || result.Pending != 101 {
						t.Fatalf("transient result=%#v err=%v", result, err)
					}
					result, err = client.SendPending(t.Context(), store)
				}
				sizes, accepted = snapshot()
				if err == nil || len(accepted) != 0 || len(sizes) != 3 {
					t.Fatalf("transient retries=%v accepted=%v err=%v", sizes, accepted, err)
				}
			case "locally_invalid":
				if err != nil || result.Delivered != 100 || len(result.Diagnostics) != 1 || len(accepted) != 100 {
					t.Fatalf("local result=%#v err=%v", result, err)
				}
			}
			pending, scanErr := store.Pending()
			blocked, readErr := os.ReadDir(filepath.Join(root, "blocked"))
			if scanErr != nil || readErr != nil {
				t.Fatalf("final spool: %v, %v", scanErr, readErr)
			}
			wantPending, wantBlocked := 0, 100
			if mode == "transient_500" {
				wantPending, wantBlocked = 101, 0
			} else if mode == "locally_invalid" {
				wantBlocked = 1
			}
			if len(pending.Entries) != wantPending || len(blocked) != wantBlocked {
				t.Fatalf("pending=%d blocked=%d", len(pending.Entries), len(blocked))
			}
			retainedBytes := spoolBytes()
			if mode == "transient_500" && retainedBytes != initialBytes {
				t.Fatal("transient retries changed retained spool bytes")
			}
			t.Logf("requests=%v accepted=%d pending=%d blocked=%d initial_bytes=%d retained_bytes=%d elapsed=%s", sizes, len(accepted), len(pending.Entries), len(blocked), initialBytes, retainedBytes, time.Since(start))
			if mode != "transient_500" {
				// Quarantine is excluded from scheduling: a newly captured tail event passes.
				item := testItem(102, "host")
				if err := store.Put(item); err != nil {
					t.Fatal(err)
				}
				result, err = client.SendPending(t.Context(), store)
				if err != nil || result.Delivered != 1 {
					t.Fatalf("later progress=%#v err=%v", result, err)
				}
				if mode == "permanent_422" && (result.ExpectedContextDelivered != 1 || result.ExpectedContextBlocked != 1) {
					t.Fatalf("optional primary dependency was not preserved: %#v", result)
				}
			}
		})
	}
}

func testSpool(t *testing.T) (*spool.Spool, spool.Item) {
	t.Helper()
	store, err := spool.New(t.TempDir(), spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	item := testItem(1, "host")
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	return store, item
}

func testItem(sequence uint32, hostID string) spool.Item {
	timestamp := time.Unix(100+int64(sequence), 0)
	event := audit.Event{
		Category: audit.CategoryAVC,
		ID:       audit.AuditEventID{Timestamp: timestamp, Sequence: sequence}, AgentReceivedAt: time.Unix(101, 0), Completion: audit.CompletionEOE,
		Records: []audit.Record{{Position: 0, Type: auparse.AUDIT_AVC, TypeName: "AVC", Timestamp: timestamp, Sequence: sequence, Raw: []byte("avc: denied")}},
	}
	observedAt := time.Unix(99, 0).UTC()
	return spool.Item{SchemaVersion: protocol.SchemaVersion, Agent: protocol.AgentMetadata{Version: "test"}, HostID: hostID, BootID: "boot", HostObservedAt: &observedAt, Event: event}
}
