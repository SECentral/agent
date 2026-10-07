package delivery

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

const maxValidationResponseBytes = 64 << 10

// This closed contract describes diagnostics, not permission to split a cohort.
func splitEligibleResponse(data []byte, entries []spool.Entry) (protocol.ErrorBody, bool) {
	var response protocol.ErrorResponse
	if len(data) > maxValidationResponseBytes || json.Unmarshal(data, &response) != nil {
		return protocol.ErrorBody{}, false
	}
	rejection := response.Error
	if rejection.Code != "invalid_request" || rejection.Phase != "pre_persistence" || len(rejection.Details) == 0 {
		return rejection, false
	}
	for _, detail := range rejection.Details {
		switch detail.Code {
		case "required", "object_required", "array_required", "invalid_type", "invalid_integer", "invalid_timestamp", "unknown_category", "unknown_completion_reason", "position_mismatch", "event_identity_mismatch", "invalid_base64", "record_type_name_mismatch", "avc_record_required", "supported_administrative_record_required":
		default:
			return rejection, false
		}
		if !eventLocalPath(detail.Path, entries) {
			return rejection, false
		}
	}
	return rejection, true
}

func pathIndex(path, prefix string) (int, string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return 0, "", false
	}
	text, suffix, ok := strings.Cut(rest, "]")
	index, err := strconv.Atoi(text)
	return index, suffix, ok && err == nil && index >= 0 && text == strconv.Itoa(index)
}

func eventLocalPath(path string, entries []spool.Entry) bool {
	index, suffix, ok := pathIndex(path, "events[")
	if !ok || index >= len(entries) {
		return false
	}
	switch suffix {
	case "", ".category", ".audit_event", ".audit_event.timestamp", ".audit_event.sequence", ".agent_received_at", ".completion_reason", ".records":
		return true
	}
	record, field, ok := pathIndex(suffix, ".records[")
	if !ok || record >= len(entries[index].Item.Event.Records) {
		return false
	}
	switch field {
	case "", ".position", ".type", ".type_name", ".timestamp", ".sequence", ".payload":
		return true
	default:
		return false
	}
}
