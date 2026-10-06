package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/secentral/agent/audit"
)

func TestIngestRequestValidatesAndSerializesRawPayload(t *testing.T) {
	event := validEvent()
	observedAt := time.Unix(99, 0).UTC()
	request := IngestRequest{
		SchemaVersion:  SchemaVersion,
		Agent:          AgentMetadata{Version: "0.1.0"},
		HostID:         "host",
		BootID:         "boot",
		HostObservedAt: &observedAt,
		Events:         []audit.Event{event},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"schema_version":4`) || strings.Contains(string(encoded), "avc: denied") || strings.Contains(string(encoded), `"selinux"`) {
		t.Fatalf("unexpected wire representation: %s", encoded)
	}
	var decoded IngestRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Events[0].Records[0].Raw) != string(event.Records[0].Raw) {
		t.Fatal("raw payload changed during request round trip")
	}
}

func TestIngestRequestReportsSemanticErrors(t *testing.T) {
	event := validEvent()
	event.Records[0].Sequence++
	request := IngestRequest{
		SchemaVersion: 1,
		Events:        []audit.Event{event},
	}
	err := request.Validate()
	validationErr, ok := err.(*ValidationError)
	if !ok || len(validationErr.Details) < 4 {
		t.Fatalf("unexpected validation error: %#v", err)
	}
	if validationErr.Details[0].Code != "unsupported_schema_version" {
		t.Fatalf("unexpected first error: %#v", validationErr.Details[0])
	}
}

func TestCheckpointTrustMaskIsNarrowAndOptional(t *testing.T) {
	for _, fields := range [][]string{nil, {}, {"enforcement"}, {"policy_identity"}, {"ports"}, {"booleans"}, {"booleans", "enforcement", "policy_identity", "ports"}, {"unsupported"}, {"enforcement", "enforcement"}} {
		request := IngestRequest{SchemaVersion: SchemaVersion, Agent: AgentMetadata{Version: "test"}, HostID: "host", BootID: "boot", Events: []audit.Event{validEvent()}, CheckpointInvalidatedFields: fields}
		wantValid := len(fields) == 0 || fields[0] != "unsupported" && (len(fields) != 2 || fields[0] != fields[1])
		if (request.Validate() == nil) != wantValid {
			t.Fatalf("wrong validation for checkpoint fields %v", fields)
		}
	}
}

func TestIngestRequestAllowsMissingCheckpointReference(t *testing.T) {
	request := IngestRequest{
		SchemaVersion: SchemaVersion,
		Agent:         AgentMetadata{Version: "test"},
		HostID:        "host",
		BootID:        "boot",
		Events:        []audit.Event{validEvent()},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "host_observed_at") {
		t.Fatalf("missing checkpoint serialized as present: %s", encoded)
	}
}

func TestAuditTypesUseSymbolicWireValues(t *testing.T) {
	observedAt := time.Unix(99, 0).UTC()
	request := IngestRequest{SchemaVersion: SchemaVersion, Agent: AgentMetadata{Version: "test"}, HostID: "host", BootID: "boot", HostObservedAt: &observedAt, Events: []audit.Event{validEvent()}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"type":"avc"`) {
		t.Fatalf("audit type is not symbolic: %s", encoded)
	}
}

func TestIngestRequestRejectsUnknownCompletionReason(t *testing.T) {
	event := validEvent()
	event.Completion = "future"
	observedAt := time.Unix(99, 0).UTC()
	request := IngestRequest{
		SchemaVersion:  SchemaVersion,
		Agent:          AgentMetadata{Version: "0.1.0"},
		HostID:         "host",
		BootID:         "boot",
		HostObservedAt: &observedAt,
		Events:         []audit.Event{event},
	}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestIngestRequestRejectsInvalidMetadataAndRecordName(t *testing.T) {
	observedAt := time.Unix(99, 0).UTC()
	request := IngestRequest{
		SchemaVersion:  SchemaVersion,
		Agent:          AgentMetadata{Version: "0.1.0"},
		HostID:         "host",
		BootID:         "boot",
		HostObservedAt: &observedAt,
		Events:         []audit.Event{validEvent()},
	}
	request.Events[0].Records[0].TypeName = "SYSCALL"
	err := request.Validate()
	if err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatal("expected validation error")
	}
	validationErr := err.(*ValidationError)
	if len(validationErr.Details) != 1 {
		t.Fatalf("unexpected validation details: %#v", validationErr.Details)
	}
}

func validEvent() audit.Event {
	timestamp := time.Unix(100, 0).UTC()
	return audit.Event{
		Category:        audit.CategoryAVC,
		ID:              audit.AuditEventID{Timestamp: timestamp, Sequence: 7},
		AgentReceivedAt: timestamp.Add(time.Millisecond),
		Completion:      audit.CompletionEOE,
		Records: []audit.Record{{
			Position:  0,
			Type:      auparse.AUDIT_AVC,
			TypeName:  "AVC",
			Timestamp: timestamp,
			Sequence:  7,
			Raw:       []byte("avc: denied"),
		}},
	}
}
