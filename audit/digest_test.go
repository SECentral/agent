package audit

import (
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestEvidenceDigestIsStableAndSensitiveToEvidence(t *testing.T) {
	timestamp := time.Unix(100, 0).UTC()
	event := Event{
		ID:         AuditEventID{Timestamp: timestamp, Sequence: 7},
		Completion: CompletionEOE,
		Records: []Record{{
			Position:  0,
			Type:      auparse.AUDIT_AVC,
			Timestamp: timestamp,
			Sequence:  7,
			Raw:       []byte("avc: denied"),
		}},
	}
	if EvidenceDigest(event) != EvidenceDigest(event) {
		t.Fatal("digest is not stable")
	}

	changed := event
	changed.Records = []Record{{
		Position:  0,
		Type:      auparse.AUDIT_AVC,
		Timestamp: timestamp,
		Sequence:  7,
		Raw:       []byte("avc: allowed"),
	}}
	if EvidenceDigest(event) == EvidenceDigest(changed) {
		t.Fatal("changed evidence has the same digest")
	}
}

func TestEvidenceDigestIsSeparateFromEventIdentity(t *testing.T) {
	timestamp := time.Unix(100, 0).UTC()
	first := Event{
		ID:         AuditEventID{Timestamp: timestamp, Sequence: 7},
		Completion: CompletionEOE,
		Records:    []Record{{Position: 0, Type: auparse.AUDIT_AVC, Timestamp: timestamp, Sequence: 7, Raw: []byte("one")}},
	}
	second := first
	second.ID.Sequence = 8
	if EvidenceDigest(first) != EvidenceDigest(second) {
		t.Fatal("identity fields changed the evidence digest")
	}

	ordered := first
	ordered.Records = []Record{{Position: 0, Type: auparse.AUDIT_AVC, Timestamp: timestamp, Sequence: 7, Raw: []byte("two")}}
	if EvidenceDigest(first) == EvidenceDigest(ordered) {
		t.Fatal("changed record evidence has the same digest")
	}
}
