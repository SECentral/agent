package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/delivery"
	"github.com/secentral/agent/metadata"
	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

func TestReplayRequestSpoolsEvents(t *testing.T) {
	event := audit.Event{
		Category:        audit.CategoryAVC,
		ID:              audit.AuditEventID{Timestamp: time.Unix(100, 0), Sequence: 1},
		AgentReceivedAt: time.Unix(101, 0), Completion: audit.CompletionEOE,
		Records: []audit.Record{{Position: 0, Type: auparse.AUDIT_AVC, TypeName: "AVC", Timestamp: time.Unix(100, 0), Sequence: 1, Raw: []byte("avc: denied")}},
	}
	observedAt := time.Unix(99, 0).UTC()
	request := protocol.IngestRequest{
		SchemaVersion:               protocol.SchemaVersion,
		Agent:                       protocol.AgentMetadata{Version: "test"},
		HostID:                      "host",
		BootID:                      "boot",
		HostObservedAt:              &observedAt,
		CheckpointInvalidatedFields: []string{"policy_identity", "ports"},
		Events:                      []audit.Event{event},
	}
	requestFile := t.TempDir() + "/request.json"
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := spool.New(t.TempDir(), spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := replayRequest(requestFile, "fallback", store); err != nil {
		t.Fatal(err)
	}
	result, err := store.Pending()
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("pending = %#v, err = %v", result, err)
	}
	if strings.Join(result.Entries[0].Item.CheckpointInvalidatedFields, ",") != "policy_identity,ports" {
		t.Fatal("replay dropped scoped trust")
	}
}

func TestPolicyLoadInvalidatesIdentityAndRejectsStaleHeartbeat(t *testing.T) {
	state := &atomic.Pointer[observedHost]{}
	state.Store(&observedHost{
		metadata:   metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{PolicyIdentity: "sha256:old", BooleanStatus: "observed", Booleans: []metadata.SELinuxBoolean{{Name: "httpd_can_network_connect", Current: new(true)}}}},
		observedAt: time.Unix(100, 0),
	})
	staleHeartbeat := state.Load()

	unknown := invalidateHostState(state, true)
	if unknown.generation != 1 || unknown.metadata.SELinux.PolicyIdentity != "" || !unknown.observedAt.IsZero() || unknown.metadata.SELinux.Booleans != nil || unknown.metadata.SELinux.BooleanStatus != "unknown" {
		t.Fatalf("policy was not invalidated: %#v", unknown)
	}
	if _, published := publishHostState(state, staleHeartbeat, observedHost{metadata: staleHeartbeat.metadata, observedAt: time.Unix(101, 0)}); published {
		t.Fatal("stale heartbeat restored the old policy identity")
	}

	refreshE1 := state.Load()
	invalidateHostState(state, true)
	if _, published := publishHostState(state, refreshE1, observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{PolicyIdentity: "sha256:obsolete"}}}); published {
		t.Fatal("an obsolete refresh restored policy after a second load")
	}
	current := state.Load()
	if _, published := publishHostState(state, current, observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{PolicyIdentity: "sha256:current", BooleanStatus: "observed", Booleans: []metadata.SELinuxBoolean{{Name: "httpd_can_network_connect", Current: new(true)}}}}}); !published {
		t.Fatal("current-generation refresh was rejected")
	}
	if got := state.Load().metadata.SELinux.PolicyIdentity; got != "sha256:current" {
		t.Fatalf("current policy identity = %q", got)
	}
	if _, published := publishHostState(state, refreshE1, observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{PolicyIdentity: "sha256:late-off"}}}); published {
		t.Fatal("late intermediate refresh overwrote the final generation")
	}
	if got := state.Load().metadata.SELinux.Booleans[0].Current; got == nil || !*got {
		t.Fatal("final On boolean state did not survive late intermediate work")
	}
	if staleHeartbeat.metadata.SELinux.Booleans[0].Current == nil || !*staleHeartbeat.metadata.SELinux.Booleans[0].Current {
		t.Fatal("invalidation mutated historical checkpoint state")
	}
}

func TestPolicyInvalidationContinuesWhileHeartbeatDeliveryIsBlocked(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	state := &atomic.Pointer[observedHost]{}
	state.Store(&observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{PolicyIdentity: "sha256:old"}}})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runHeartbeatLoop(ctx, delivery.Client{Endpoint: server.URL + "/events", HTTPClient: server.Client()}, state, make(chan struct{}), time.Hour, "test", newLogger(false))
	}()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("heartbeat did not reach the blocked delivery")
	}

	unknown := invalidateHostState(state, true)
	if unknown.metadata.SELinux.PolicyIdentity != "" {
		t.Fatal("policy identity remained usable while heartbeat delivery was blocked")
	}
	close(release)
	cancel()
	<-done
}

func TestEnforcementInvalidationPreservesPolicyAndRejectsLatePermissiveRefresh(t *testing.T) {
	state := &atomic.Pointer[observedHost]{}
	initial := &observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{
		PolicyIdentity: "sha256:stable", Enforcement: metadata.Enforcing, BooleanStatus: "observed",
		Booleans: []metadata.SELinuxBoolean{{Name: "httpd_can_network_connect", Current: new(true)}}}}, observedAt: time.Unix(100, 0)}
	state.Store(initial)
	unknown := invalidateHostState(state, false)
	if unknown.metadata.SELinux.Enforcement != metadata.Unknown || unknown.generation != 1 {
		t.Fatalf("mode not invalidated: %#v", unknown)
	}
	if unknown.metadata.SELinux.PolicyIdentity != "sha256:stable" || !unknown.observedAt.Equal(initial.observedAt) || len(unknown.metadata.SELinux.Booleans) != 1 || unknown.metadata.SELinux.BooleanStatus != "observed" {
		t.Fatal("mode change destroyed unrelated checkpoint evidence")
	}
	if len(unknown.checkpointInvalidatedFields) != 1 || unknown.checkpointInvalidatedFields[0] != "enforcement" {
		t.Fatal("old enforcement reference remained trusted")
	}
	permissiveRefresh := state.Load()
	invalidateHostState(state, false)
	current := state.Load()
	refreshed := observedHost{metadata: initial.metadata, observedAt: time.Unix(104, 0)}
	if _, published := publishHostState(state, current, refreshed); !published {
		t.Fatal("current Enforcing refresh rejected")
	}
	refreshed.metadata.SELinux.Enforcement = metadata.Permissive
	if _, published := publishHostState(state, permissiveRefresh, refreshed); published {
		t.Fatal("stale Permissive refresh replaced the final generation")
	}
	final := state.Load()
	if final.metadata.SELinux.Enforcement != metadata.Enforcing || final.generation != 2 || final.metadata.SELinux.PolicyIdentity != "sha256:stable" || len(final.checkpointInvalidatedFields) != 0 {
		t.Fatalf("wrong final state: %#v", final)
	}
	if initial.metadata.SELinux.Enforcement != metadata.Enforcing {
		t.Fatal("historical checkpoint mutated")
	}
}

func TestCheckpointTimestampIsAfterStateCollection(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "boolean-read-completed")
	tool := filepath.Join(dir, "getsebool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nsleep 0.05\ntouch \"$CHECKPOINT_MARKER\"\nprintf 'httpd_can_network_connect --> on\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHECKPOINT_MARKER", marker)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	checkpoint := collectMetadata(metadata.HostMetadata{}, newLogger(false))
	info, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.observedAt.Before(info.ModTime()) {
		t.Fatalf("checkpoint time %s predates the completed boolean read %s", checkpoint.observedAt, info.ModTime())
	}
}

func TestPortInvalidationRacePreservesOtherDimensionsAndCombinesMasks(t *testing.T) {
	state := &atomic.Pointer[observedHost]{}
	initial := &observedHost{metadata: metadata.HostMetadata{SELinux: metadata.SELinuxMetadata{
		PolicyIdentity: "sha256:old", Enforcement: metadata.Enforcing, BooleanStatus: "observed",
		Booleans: []metadata.SELinuxBoolean{{Name: "nis_enabled", Current: new(false)}},
		Policy:   metadata.PolicyMetadata{PortInventory: &metadata.PortInventory{Status: "observed"}},
	}}, observedAt: time.Unix(100, 0)}
	state.Store(initial)
	first := invalidateHostState(state, false, "ports", "policy_identity")
	if first.metadata.SELinux.PolicyIdentity != "" || first.metadata.SELinux.Policy.PortInventory.Status != "unknown" ||
		first.metadata.SELinux.Enforcement != metadata.Enforcing || first.metadata.SELinux.BooleanStatus != "observed" ||
		!first.observedAt.Equal(initial.observedAt) || len(first.metadata.SELinux.Booleans) != 1 {
		t.Fatalf("wrong scoped state: %#v", first)
	}
	second := invalidateHostState(state, false, "ports", "policy_identity")
	final := observedHost{metadata: initial.metadata, observedAt: time.Unix(104, 0)}
	if _, ok := publishHostState(state, second, final); !ok {
		t.Fatal("final refresh rejected")
	}
	if _, ok := publishHostState(state, first, final); ok {
		t.Fatal("late intermediate inventory published")
	}
	mode := invalidateHostState(state, false)
	combined := invalidateHostState(state, false, "ports", "policy_identity")
	if strings.Join(combined.checkpointInvalidatedFields, ",") != "enforcement,policy_identity,ports" {
		t.Fatal("mask was overwritten")
	}
	if len(mode.checkpointInvalidatedFields) != 1 {
		t.Fatal("historical mask mutated")
	}
	if initial.metadata.SELinux.Policy.PortInventory.Status != "observed" {
		t.Fatal("historical ports mutated")
	}
}

func TestDebugEnvironmentFlag(t *testing.T) {
	t.Setenv("SECENTRAL_DEBUG", "true")
	if !envBool("SECENTRAL_DEBUG") {
		t.Fatal("SECENTRAL_DEBUG=true was not enabled")
	}
	t.Setenv("SECENTRAL_DEBUG", "false")
	if envBool("SECENTRAL_DEBUG") {
		t.Fatal("SECENTRAL_DEBUG=false was enabled")
	}
}

func TestExpectedContextInspectionIsAfterAVCSpoolAndDeduplicated(t *testing.T) {
	root := t.TempDir()
	store, err := spool.New(root, spool.Config{MaxEvents: 2500})
	if err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(t.TempDir(), "calls")
	resolverDir := t.TempDir()
	resolver := filepath.Join(resolverDir, "matchpathcon")
	script := "#!/bin/sh\nprintf x >> \"$COUNT_FILE\"\nprintf 'system_u:object_r:expected_t:s0\\n'\n"
	if err := os.WriteFile(resolver, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COUNT_FILE", countPath)
	t.Setenv("PATH", resolverDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	observedAt := time.Unix(99, 0).UTC()
	inspector := newExpectedContextInspector(t.Context(), store, "test", newLogger(false))
	for sequence := range uint32(2000) {
		event := fileContextAVCEvent(sequence + 1)
		if err := store.Put(spool.Item{
			SchemaVersion: protocol.SchemaVersion,
			Agent:         protocol.AgentMetadata{Version: "test"},
			HostID:        "host", BootID: "boot", HostObservedAt: &observedAt, Event: event,
		}); err != nil {
			t.Fatal(err)
		}
		inspector.enqueue("host", "boot", &observedAt, event)
	}
	inspector.close()

	if pending, err := store.Pending(); err != nil || len(pending.Entries) != 2000 {
		t.Fatalf("AVCs pending = %d, err=%v", len(pending.Entries), err)
	}
	observations, err := store.ExpectedContextPending()
	if err != nil || len(observations.Entries) != 1 {
		t.Fatalf("expected-context entries = %d, err=%v", len(observations.Entries), err)
	}
	calls, err := os.ReadFile(countPath)
	if err != nil || string(calls) != "x" {
		t.Fatalf("matchpathcon calls = %q, err=%v", calls, err)
	}
}

func TestExpectedContextTimeoutLeavesRawAVCSpoolUnaffected(t *testing.T) {
	store, err := spool.New(t.TempDir(), spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	resolverDir := t.TempDir()
	resolver := filepath.Join(resolverDir, "matchpathcon")
	if err := os.WriteFile(resolver, []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", resolverDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	observedAt := time.Unix(99, 0).UTC()
	event := fileContextAVCEvent(1)
	if err := store.Put(spool.Item{
		SchemaVersion: protocol.SchemaVersion,
		Agent:         protocol.AgentMetadata{Version: "test"},
		HostID:        "host", BootID: "boot", HostObservedAt: &observedAt, Event: event,
	}); err != nil {
		t.Fatal(err)
	}
	inspector := newExpectedContextInspector(t.Context(), store, "test", newLogger(false))
	inspector.enqueue("host", "boot", &observedAt, event)
	inspector.close()

	if pending, err := store.Pending(); err != nil || len(pending.Entries) != 1 {
		t.Fatalf("raw AVC pending = %d, err=%v", len(pending.Entries), err)
	}
	observations, err := store.ExpectedContextPending()
	if err != nil || len(observations.Entries) != 1 {
		t.Fatalf("expected-context entries = %d, err=%v", len(observations.Entries), err)
	}
	if got := observations.Entries[0].Item.Observation; got.Status != "error" || got.Reason != "resolver_timeout" {
		t.Fatalf("timeout observation = %#v", got)
	}
}

func TestExpectedContextInspectorDoesNotResolveBasenameOnlyAVC(t *testing.T) {
	root := t.TempDir()
	store, err := spool.New(root, spool.Config{})
	if err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(t.TempDir(), "calls")
	resolverDir := t.TempDir()
	resolver := filepath.Join(resolverDir, "matchpathcon")
	if err := os.WriteFile(resolver, []byte("#!/bin/sh\nprintf x >> \"$COUNT_FILE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COUNT_FILE", countPath)
	t.Setenv("PATH", resolverDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	timestamp := time.Unix(100, 0).UTC()
	event := audit.Event{
		Category:        audit.CategoryAVC,
		ID:              audit.AuditEventID{Timestamp: timestamp, Sequence: 1},
		AgentReceivedAt: timestamp.Add(time.Millisecond),
		Completion:      audit.CompletionEOE,
		Records: []audit.Record{
			{Position: 0, Type: auparse.AUDIT_AVC, TypeName: "AVC", Timestamp: timestamp, Sequence: 1, Raw: []byte(`type=AVC avc: denied { read } name="basename" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file`)},
			{Position: 1, Type: auparse.AUDIT_EOE, TypeName: "EOE", Timestamp: timestamp, Sequence: 1, Raw: []byte("type=EOE")},
		},
	}
	if err := store.Put(spool.Item{SchemaVersion: protocol.SchemaVersion, Agent: protocol.AgentMetadata{Version: "test"}, HostID: "host", BootID: "boot", Event: event}); err != nil {
		t.Fatal(err)
	}
	inspector := newExpectedContextInspector(t.Context(), store, "test", newLogger(false))
	inspector.enqueue("host", "boot", nil, event)
	inspector.close()
	if _, err := os.Stat(countPath); !os.IsNotExist(err) {
		t.Fatalf("matchpathcon was invoked for basename-only evidence: %v", err)
	}
	if pending, err := store.Pending(); err != nil || len(pending.Entries) != 1 {
		t.Fatalf("basename AVC pending = %d, err=%v", len(pending.Entries), err)
	}
}

func fileContextAVCEvent(sequence uint32) audit.Event {
	timestamp := time.Unix(100, int64(sequence)).UTC()
	records := []string{
		fmt.Sprintf("type=AVC msg=audit(%d.%09d:%d): avc: denied { read } for name=\"probe\" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file", timestamp.Unix(), timestamp.Nanosecond(), sequence),
		fmt.Sprintf("type=PATH msg=audit(%d.%09d:%d): item=0 name=\"/var/www/html/probe\" inode=10 dev=fc:00 mode=0100644", timestamp.Unix(), timestamp.Nanosecond(), sequence),
		fmt.Sprintf("type=EOE msg=audit(%d.%09d:%d):", timestamp.Unix(), timestamp.Nanosecond(), sequence),
	}
	event := audit.Event{
		Category:        audit.CategoryAVC,
		ID:              audit.AuditEventID{Timestamp: timestamp, Sequence: sequence},
		AgentReceivedAt: timestamp.Add(time.Millisecond),
		Completion:      audit.CompletionEOE,
	}
	for position, payload := range records {
		var messageType auparse.AuditMessageType
		switch {
		case strings.HasPrefix(payload, "type=AVC"):
			messageType = auparse.AUDIT_AVC
		case strings.HasPrefix(payload, "type=PATH"):
			messageType = auparse.AUDIT_PATH
		default:
			messageType = auparse.AUDIT_EOE
		}
		event.Records = append(event.Records, audit.Record{
			Position: position, Type: messageType, TypeName: messageType.String(),
			Timestamp: timestamp, Sequence: sequence, Raw: []byte(payload),
		})
	}
	return event
}

func TestArtifactRequestDoesNotUploadBytesAfterLoadedPolicyChanges(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { uploads.Add(1) }))
	defer server.Close()
	client := delivery.Client{Endpoint: server.URL + "/events", IngestionKey: "secret"}

	err := uploadPolicyArtifactIfIdentityMatches(t.Context(), client, "host", "sha256:requested", "sha256:current", []byte("current policy"))
	if err == nil {
		t.Fatal("expected a policy identity mismatch")
	}
	if uploads.Load() != 0 {
		t.Fatalf("uploaded bytes %d times", uploads.Load())
	}
}

func TestCopyRawAuditMessageOwnsReceiveBuffer(t *testing.T) {
	raw := []byte("type=AVC avc: denied")
	message := copyRawAuditMessage(&libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: raw})
	raw[0] = 'X'

	if !bytes.Equal(message.Data, []byte("type=AVC avc: denied")) {
		t.Fatalf("copied data = %q", message.Data)
	}
}

func TestAuditRecordTypeMismatch(t *testing.T) {
	if !auditRecordTypeMismatch(&libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:7): arch=c000003e")}) {
		t.Fatal("expected AVC/SYSCALL mismatch")
	}
	if auditRecordTypeMismatch(&libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:7): avc: denied")}) {
		t.Fatal("valid AVC was reported as a mismatch")
	}
}
