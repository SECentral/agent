package protocol

import (
	"testing"
	"time"
)

func TestExpectedContextObservationValidatesResolvedAndUnavailableResults(t *testing.T) {
	request := validExpectedContextRequest()
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}

	request.Observation = ExpectedContextObservation{
		Path: "/srv/file", ObjectClass: "file", ObservedAt: time.Unix(101, 0).UTC(),
		Resolver: "matchpathcon", Status: "unavailable", Reason: "resolver_unavailable",
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExpectedContextObservationRejectsInventedOrIncompleteEvidence(t *testing.T) {
	request := validExpectedContextRequest()
	request.Observation.Path = "basename-only"
	if err := request.Validate(); err == nil {
		t.Fatal("relative path was accepted")
	}

	request = validExpectedContextRequest()
	request.Observation.ExpectedContext = ""
	if err := request.Validate(); err == nil {
		t.Fatal("resolved observation without expected context was accepted")
	}

	request = validExpectedContextRequest()
	request.Observation.Status = "pending"
	if err := request.Validate(); err == nil {
		t.Fatal("unknown observation status was accepted")
	}
}

func validExpectedContextRequest() ExpectedContextObservationRequest {
	return ExpectedContextObservationRequest{
		SchemaVersion: ExpectedContextSchemaVersion,
		Agent:         AgentMetadata{Version: "test"},
		HostID:        "host",
		BootID:        "boot",
		AuditEvent:    AuditEventReference{Timestamp: time.Unix(100, 0).UTC(), Sequence: 7},
		Observation: ExpectedContextObservation{
			Path: "/srv/file", ObjectClass: "file", FileType: "file",
			ExpectedContext: "system_u:object_r:expected_t:s0", ObservedAt: time.Unix(101, 0).UTC(),
			Resolver: "matchpathcon", Status: "resolved",
		},
	}
}
