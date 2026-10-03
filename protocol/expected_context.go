package protocol

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const ExpectedContextSchemaVersion = 1

type ExpectedContextObservationRequest struct {
	SchemaVersion  int                        `json:"schema_version"`
	Agent          AgentMetadata              `json:"agent"`
	HostID         string                     `json:"host_id"`
	BootID         string                     `json:"boot_id"`
	AuditEvent     AuditEventReference        `json:"audit_event"`
	HostObservedAt *time.Time                 `json:"host_observed_at,omitempty"`
	Observation    ExpectedContextObservation `json:"observation"`
}

type AuditEventReference struct {
	Timestamp time.Time `json:"timestamp"`
	Sequence  uint32    `json:"sequence"`
}

type ExpectedContextObservation struct {
	Path            string    `json:"path"`
	ObjectClass     string    `json:"object_class"`
	FileType        string    `json:"file_type,omitempty"`
	ExpectedContext string    `json:"expected_context,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	Resolver        string    `json:"resolver"`
	Status          string    `json:"status"`
	Reason          string    `json:"reason,omitempty"`
}

func (r ExpectedContextObservationRequest) Validate() error {
	if r.SchemaVersion != ExpectedContextSchemaVersion {
		return fmt.Errorf("unsupported expected-context schema version %d", r.SchemaVersion)
	}
	if r.Agent.Version == "" || r.HostID == "" || r.BootID == "" {
		return fmt.Errorf("agent version, host ID, and boot ID are required")
	}
	if r.AuditEvent.Timestamp.IsZero() {
		return fmt.Errorf("audit event timestamp is required")
	}
	if r.HostObservedAt != nil && r.HostObservedAt.IsZero() {
		return fmt.Errorf("host observation timestamp is invalid")
	}
	observation := r.Observation
	if !path.IsAbs(observation.Path) || len(observation.Path) > 4096 || strings.ContainsRune(observation.Path, '\x00') {
		return fmt.Errorf("observation path must be a complete absolute path")
	}
	if observation.ObjectClass == "" || len(observation.ObjectClass) > 64 || observation.ObservedAt.IsZero() || observation.Resolver != "matchpathcon" {
		return fmt.Errorf("object class, observation time, and matchpathcon resolver are required")
	}
	if len(observation.Reason) > 256 {
		return fmt.Errorf("observation reason is too long")
	}
	switch observation.Status {
	case "resolved":
		if !validMatchPathconType(observation.FileType) || observation.ExpectedContext == "" || len(observation.ExpectedContext) > 512 || observation.Reason != "" {
			return fmt.Errorf("resolved observations require a supported file type and expected context")
		}
	case "unavailable", "error":
		if observation.ExpectedContext != "" || observation.Reason == "" {
			return fmt.Errorf("unavailable and error observations require a reason and no expected context")
		}
		if observation.FileType != "" && !validMatchPathconType(observation.FileType) {
			return fmt.Errorf("unsupported matchpathcon file type %q", observation.FileType)
		}
	default:
		return fmt.Errorf("unknown expected-context status %q", observation.Status)
	}
	return nil
}

func validMatchPathconType(value string) bool {
	switch value {
	case "file", "dir", "pipe", "chr_file", "blk_file", "lnk_file", "sock_file":
		return true
	default:
		return false
	}
}
