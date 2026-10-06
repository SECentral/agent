package protocol

import (
	"fmt"
	"slices"
	"time"

	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/metadata"
)

const SchemaVersion = 4
const HeartbeatSchemaVersion = 2

type AgentMetadata struct {
	Version string `json:"version"`
}

type IngestRequest struct {
	SchemaVersion               int           `json:"schema_version"`
	Agent                       AgentMetadata `json:"agent"`
	HostID                      string        `json:"host_id"`
	BootID                      string        `json:"boot_id"`
	HostObservedAt              *time.Time    `json:"host_observed_at,omitempty"`
	CheckpointInvalidatedFields []string      `json:"checkpoint_invalidated_fields,omitempty"`
	Events                      []audit.Event `json:"events"`
}

type HeartbeatRequest struct {
	SchemaVersion  int                   `json:"schema_version"`
	Agent          AgentMetadata         `json:"agent"`
	HostObservedAt time.Time             `json:"host_observed_at"`
	Host           metadata.HostMetadata `json:"host"`
}

type HeartbeatResponse struct {
	PolicyArtifactRequired bool   `json:"policy_artifact_required"`
	PolicyIdentity         string `json:"policy_identity,omitempty"`
}

type ValidationDetail struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string             `json:"code"`
	Message string             `json:"message"`
	Details []ValidationDetail `json:"details,omitempty"`
}

type ValidationError struct {
	Details []ValidationDetail
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("request validation failed (%d errors)", len(e.Details))
}

func (r IngestRequest) Validate() error {
	var details []ValidationDetail
	if r.SchemaVersion != SchemaVersion {
		details = append(details, ValidationDetail{Path: "schema_version", Code: "unsupported_schema_version"})
	}
	if r.HostID == "" {
		details = append(details, ValidationDetail{Path: "host_id", Code: "required"})
	}
	if r.BootID == "" {
		details = append(details, ValidationDetail{Path: "boot_id", Code: "required"})
	}
	if r.Agent.Version == "" {
		details = append(details, ValidationDetail{Path: "agent.version", Code: "required"})
	}
	for i, field := range r.CheckpointInvalidatedFields {
		if !slices.Contains([]string{"enforcement", "ports", "policy_identity", "booleans", "file_context_mappings"}, field) || slices.Contains(r.CheckpointInvalidatedFields[:i], field) {
			details = append(details, ValidationDetail{Path: "checkpoint_invalidated_fields", Code: "invalid_checkpoint_fields"})
		}
	}
	if len(r.Events) == 0 {
		details = append(details, ValidationDetail{Path: "events", Code: "required"})
	}
	for i, event := range r.Events {
		path := fmt.Sprintf("events[%d]", i)
		if event.Category != audit.CategoryAVC && event.Category != audit.CategorySELinuxAdministrative {
			details = append(details, ValidationDetail{Path: path + ".category", Code: "unknown_category"})
		}
		if event.ID.Timestamp.IsZero() {
			details = append(details, ValidationDetail{Path: path + ".audit_event.timestamp", Code: "required"})
		}
		if event.AgentReceivedAt.IsZero() {
			details = append(details, ValidationDetail{Path: path + ".agent_received_at", Code: "required"})
		}
		if !validCompletion(event.Completion) {
			details = append(details, ValidationDetail{Path: path + ".completion_reason", Code: "unknown_completion_reason"})
		}
		if len(event.Records) == 0 {
			details = append(details, ValidationDetail{Path: path + ".records", Code: "required"})
		}
		for j, record := range event.Records {
			recordPath := fmt.Sprintf("%s.records[%d]", path, j)
			if record.Position != j {
				details = append(details, ValidationDetail{Path: recordPath + ".position", Code: "position_mismatch"})
			}
			if record.TypeName != record.Type.String() {
				details = append(details, ValidationDetail{Path: recordPath + ".type_name", Code: "record_type_name_mismatch"})
			}
			if record.Timestamp.IsZero() || !record.Timestamp.Equal(event.ID.Timestamp) {
				details = append(details, ValidationDetail{Path: recordPath + ".timestamp", Code: "event_identity_mismatch"})
			}
			if record.Sequence != event.ID.Sequence {
				details = append(details, ValidationDetail{Path: recordPath + ".sequence", Code: "event_identity_mismatch"})
			}
			if len(record.Raw) == 0 {
				details = append(details, ValidationDetail{Path: recordPath + ".payload", Code: "required"})
			}
		}
	}
	if len(details) > 0 {
		return &ValidationError{Details: details}
	}
	return nil
}

func validCompletion(reason audit.CompletionReason) bool {
	switch reason {
	case audit.CompletionEOE, audit.CompletionTimeout, audit.CompletionCapacity, audit.CompletionShutdown:
		return true
	default:
		return false
	}
}
