package audit

import (
	"encoding/json"
	"testing"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestEventJSONRoundTripPreservesRawEvidence(t *testing.T) {
	raw := []byte("audit(100.000:7): avc: denied \xff")
	a := NewAssembler(Config{Timeout: time.Second, MaxInFlight: 10})
	if _, err := a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: raw}, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	event := a.Close()[0]

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Records[0].Raw) != string(raw) {
		t.Fatalf("raw payload changed: %v", decoded.Records[0].Raw)
	}
	if decoded.Records[0].TypeName != "AVC" || decoded.Records[0].Position != 0 {
		t.Fatalf("metadata not preserved: %#v", decoded.Records[0])
	}
	if decoded.Completion != CompletionShutdown || !decoded.AgentReceivedAt.Equal(event.AgentReceivedAt) {
		t.Fatalf("envelope not preserved: %#v", decoded)
	}

	parsed, err := auparse.Parse(decoded.Records[0].Type, string(decoded.Records[0].Raw))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sequence != event.ID.Sequence || !parsed.Timestamp.Equal(event.ID.Timestamp) {
		t.Fatalf("stored evidence cannot be reparsed: %#v", parsed)
	}
}

func TestUnknownRecordTypeSurvivesJSON(t *testing.T) {
	event := Event{
		ID:         AuditEventID{Timestamp: time.Unix(100, 0), Sequence: 1},
		Completion: CompletionEOE,
		Records:    []Record{{Position: 0, Type: 65500, TypeName: "UNKNOWN[65500]", Raw: []byte("audit(100.000:1): opaque")}},
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Records[0].Type != 65500 || decoded.Records[0].TypeName != "UNKNOWN[65500]" {
		t.Fatalf("unknown record metadata changed: %#v", decoded.Records[0])
	}
}
