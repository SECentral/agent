package spool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/protocol"
)

func TestSpoolSurvivesReopenAndAcknowledgement(t *testing.T) {
	root := t.TempDir()
	item := testItem()
	item.CheckpointInvalidatedFields = []string{"booleans", "enforcement", "policy_identity", "ports"}
	encoded, err := json.Marshal(item)
	if err != nil || strings.Contains(string(encoded), `"selinux"`) {
		t.Fatalf("spool item contains host state: %s, %v", encoded, err)
	}
	spool, err := New(root, Config{MaxBytes: 1 << 20, MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(item); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(root, Config{MaxBytes: 1 << 20, MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reopened.Pending()
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("pending entries: %v, %v", result.Entries, err)
	}
	if result.Entries[0].Item.Event.Records[0].Raw[0] != 'a' {
		t.Fatal("stored event changed")
	}
	if fields := result.Entries[0].Item.CheckpointInvalidatedFields; strings.Join(fields, ",") != "booleans,enforcement,policy_identity,ports" {
		t.Fatal("checkpoint trust mask lost on reopen")
	}
	gotCheckpoint, wantCheckpoint := result.Entries[0].Item.HostObservedAt, item.HostObservedAt
	if gotCheckpoint == nil || wantCheckpoint == nil || !gotCheckpoint.Equal(*wantCheckpoint) || result.Entries[0].Item.HostID != item.HostID || result.Entries[0].Item.BootID != item.BootID {
		t.Fatal("stored host reference changed")
	}
	if err := reopened.Ack(result.Entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Ack(result.Entries[0].ID); err != nil {
		t.Fatal("acknowledgement retry was not idempotent")
	}
	result, err = reopened.Pending()
	if err != nil || len(result.Entries) != 0 {
		t.Fatalf("acknowledged entry remains: %v, %v", result.Entries, err)
	}
}

func TestSpoolAllowsConcurrentCaptureAndDelivery(t *testing.T) {
	store, err := New(t.TempDir(), Config{MaxBytes: 1 << 20, MaxEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	const count = 32
	writeDone := make(chan struct{})
	writeErr := make(chan error, 1)
	var writer sync.WaitGroup
	writer.Go(func() {
		defer close(writeDone)
		for sequence := range uint32(count) {
			if err := store.Put(testItemWithSequence(sequence + 1)); err != nil {
				writeErr <- err
				return
			}
		}
	})

	delivered := 0
	for {
		scan, err := store.Pending()
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range scan.Entries {
			if err := store.Ack(entry.ID); err != nil {
				t.Fatal(err)
			}
			delivered++
		}
		select {
		case <-writeDone:
			writer.Wait()
			select {
			case err := <-writeErr:
				t.Fatal(err)
			default:
			}
			for {
				remaining, err := store.Pending()
				if err != nil {
					t.Fatal(err)
				}
				if len(remaining.Entries) == 0 {
					break
				}
				for _, entry := range remaining.Entries {
					if err := store.Ack(entry.ID); err != nil {
						t.Fatal(err)
					}
					delivered++
				}
			}
			if delivered != count {
				t.Fatalf("delivered %d of %d events", delivered, count)
			}
			return
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestSpoolQuarantinesCorruptEntriesAndCleansTemporaryFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pending", "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tmp", "partial.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := spool.Pending(); err != nil || len(result.Diagnostics) != 1 {
		t.Fatalf("expected corrupt-entry diagnostic: %v, %#v", err, result)
	}
	if _, err := os.Stat(filepath.Join(root, "blocked", "bad.json")); err != nil {
		t.Fatal("corrupt entry was not quarantined")
	}
	if _, err := os.Stat(filepath.Join(root, "tmp", "partial.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary entry was not cleaned")
	}
}

func TestSpoolRejectsCapacityWithoutDeletingExistingEntries(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{MaxBytes: 1, MaxEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItem()); err == nil {
		t.Fatal("expected capacity error")
	}
	result, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("capacity failure created entries: %d", len(result.Entries))
	}
}

func TestSpoolBlocksEntryWithoutDeletingEvidence(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItem()); err != nil {
		t.Fatal(err)
	}
	result, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Block(result.Entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "blocked", result.Entries[0].ID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolCountsBlockedEntriesAndMakesTransitionsIdempotent(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{MaxBytes: 1 << 20, MaxEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItem()); err != nil {
		t.Fatal(err)
	}
	result, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Block(result.Entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := spool.Block(result.Entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItemWithSequence(8)); err == nil {
		t.Fatal("blocked entry did not count toward capacity")
	}
	if err := spool.Ack(result.Entries[0].ID); err != nil {
		t.Fatal("acknowledging an already absent entry was not idempotent")
	}
}

func TestSpoolQuarantinesEntriesWithInvalidDigestOrIdentity(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	item := testItem()
	if err := spool.Put(item); err != nil {
		t.Fatal(err)
	}
	result, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "pending", result.Entries[0].ID+".json")
	stored := result.Entries[0].Item
	stored.Event.Records[0].Raw = []byte("changed")
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = spool.Pending()
	if err != nil || len(result.Entries) != 0 || len(result.Diagnostics) != 1 {
		t.Fatalf("invalid entry was accepted: %#v, %v", result, err)
	}
}

func TestSpoolQuarantinesFilenameIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	item := testItem()
	item.SpoolVersion = SpoolVersion
	item.SchemaVersion = protocol.SchemaVersion
	item.EvidenceDigest = audit.EvidenceDigest(item.Event)
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pending", "wrong.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := spool.Pending()
	if err != nil || len(result.Entries) != 0 || len(result.Diagnostics) != 1 {
		t.Fatalf("identity mismatch was accepted: %#v, %v", result, err)
	}
}

func TestSpoolKeepsHealthyEntriesWhenOneIsCorrupt(t *testing.T) {
	root := t.TempDir()
	spool, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItem()); err != nil {
		t.Fatal(err)
	}
	if err := spool.Put(testItemWithSequence(8)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pending", "corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := spool.Pending()
	if err != nil || len(result.Entries) != 2 || len(result.Diagnostics) != 1 {
		t.Fatalf("healthy entries were blocked: %#v, %v", result, err)
	}
}

func TestExpectedContextObservationHasSeparateDurableCapacity(t *testing.T) {
	root := t.TempDir()
	store, err := New(root, Config{MaxBytes: 1 << 20, MaxEvents: 1, MaxExpectedContextBytes: 1 << 20, MaxExpectedContextObservations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(testItem()); err != nil {
		t.Fatal(err)
	}
	observation := testExpectedContextObservation()
	if err := store.PutExpectedContextObservation(observation); err != nil {
		t.Fatal(err)
	}
	if err := store.PutExpectedContextObservation(observation); err != nil {
		t.Fatalf("identical retry was not idempotent: %v", err)
	}
	if err := store.Put(testItemWithSequence(8)); err == nil {
		t.Fatal("event capacity was not enforced")
	}

	reopened, err := New(root, Config{MaxBytes: 1 << 20, MaxEvents: 1, MaxExpectedContextBytes: 1 << 20, MaxExpectedContextObservations: 1})
	if err != nil {
		t.Fatal(err)
	}
	events, err := reopened.Pending()
	if err != nil || len(events.Entries) != 1 {
		t.Fatalf("AVC entries = %d, err=%v", len(events.Entries), err)
	}
	observations, err := reopened.ExpectedContextPending()
	if err != nil || len(observations.Entries) != 1 || observations.Entries[0].Item.Observation.ExpectedContext != observation.Observation.ExpectedContext {
		t.Fatalf("expected-context entries = %#v, err=%v", observations, err)
	}
	if err := reopened.AckExpectedContextObservation(observations.Entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if pending, err := reopened.Pending(); err != nil || len(pending.Entries) != 1 {
		t.Fatalf("acknowledging optional evidence changed AVC spool: %d, %v", len(pending.Entries), err)
	}
}

func testExpectedContextObservation() protocol.ExpectedContextObservationRequest {
	timestamp := time.Unix(100, 0).UTC()
	return protocol.ExpectedContextObservationRequest{
		SchemaVersion: protocol.ExpectedContextSchemaVersion,
		Agent:         protocol.AgentMetadata{Version: "test"},
		HostID:        "host",
		BootID:        "boot",
		AuditEvent:    protocol.AuditEventReference{Timestamp: timestamp, Sequence: 7},
		Observation: protocol.ExpectedContextObservation{
			Path: "/srv/file", ObjectClass: "file", FileType: "file",
			ExpectedContext: "system_u:object_r:expected_t:s0", ObservedAt: timestamp.Add(time.Second),
			Resolver: "matchpathcon", Status: "resolved",
		},
	}
}

func testItem() Item {
	return testItemWithSequence(7)
}

func testItemWithSequence(sequence uint32) Item {
	timestamp := time.Unix(100, 0).UTC()
	event := audit.Event{
		Category:        audit.CategoryAVC,
		ID:              audit.AuditEventID{Timestamp: timestamp, Sequence: sequence},
		AgentReceivedAt: timestamp.Add(time.Second),
		Completion:      audit.CompletionEOE,
		Records: []audit.Record{{
			Position: 0, Type: auparse.AUDIT_AVC, TypeName: "AVC",
			Timestamp: timestamp, Sequence: sequence, Raw: []byte("avc: denied"),
		}},
	}
	observedAt := timestamp.Add(-time.Second)
	return Item{
		SchemaVersion:  protocol.SchemaVersion,
		HostID:         "host",
		BootID:         "boot",
		HostObservedAt: &observedAt,
		Agent:          protocol.AgentMetadata{Version: "0.1.0"},
		Event:          event,
	}
}
