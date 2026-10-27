package spool

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/protocol"
)

func TestBufferedEventsRetainCollectionOrderAndEvidenceAfterReopen(t *testing.T) {
	data, err := os.ReadFile("../audit/testdata/buffered-events.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Request protocol.IngestRequest `json:"request"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	request := capture.Request
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for _, event := range slices.Backward(request.Events) {
			if err := store.Put(Item{SchemaVersion: request.SchemaVersion, Agent: request.Agent,
				HostID: request.HostID, BootID: request.BootID, HostObservedAt: request.HostObservedAt, Event: event}); err != nil {
				t.Fatal(err)
			}
		}
	}
	store, err = New(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	scan, err := store.Pending()
	if err != nil || len(scan.Entries) != len(request.Events) || len(scan.Diagnostics) != 0 {
		t.Fatalf("pending events: %#v, %v", scan, err)
	}
	var ids []string
	for i, entry := range scan.Entries {
		got, want := entry.Item, request.Events[i]
		if got.HostID != request.HostID || got.BootID != request.BootID || got.Event.ID != want.ID ||
			!got.Event.AgentReceivedAt.Equal(want.AgentReceivedAt) || audit.EvidenceDigest(got.Event) != audit.EvidenceDigest(want) {
			t.Fatalf("buffered identity, collection order or evidence changed: %v", got.Event.ID)
		}
		ids = append(ids, entry.ID)
	}
	files, err := os.ReadDir(store.pending)
	if err != nil {
		t.Fatal(err)
	}
	var filenames []string
	for _, file := range files {
		filenames = append(filenames, strings.TrimSuffix(file.Name(), ".json"))
	}
	if slices.Equal(ids, filenames) {
		t.Fatal("capture must exercise collection order differing from filename order")
	}
}
