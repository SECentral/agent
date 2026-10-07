package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/metadata"
	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

const DefaultMaxBatchEvents = 100

type Client struct {
	Endpoint       string
	IngestionKey   string
	HTTPClient     *http.Client
	MaxBatchEvents int
	Logger         *slog.Logger
}

func (c Client) SendHeartbeat(ctx context.Context, host metadata.HostMetadata, hostObservedAt time.Time, version string) (protocol.HeartbeatResponse, error) {
	request := protocol.HeartbeatRequest{SchemaVersion: protocol.HeartbeatSchemaVersion, Agent: protocol.AgentMetadata{Version: version}, HostObservedAt: hostObservedAt, Host: host}
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.HeartbeatResponse{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.heartbeatEndpoint(), bytes.NewReader(body))
	if err != nil {
		return protocol.HeartbeatResponse{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+c.IngestionKey)
	response, err := c.httpClient().Do(httpRequest)
	if err != nil {
		return protocol.HeartbeatResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return protocol.HeartbeatResponse{}, fmt.Errorf("heartbeat failed: HTTP %d", response.StatusCode)
	}
	var result protocol.HeartbeatResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil && !errors.Is(err, io.EOF) {
		return protocol.HeartbeatResponse{}, fmt.Errorf("decode heartbeat response: %w", err)
	}
	return result, nil
}

func (c Client) UploadPolicyArtifact(ctx context.Context, hostID, policyIdentity string, artifact []byte) error {
	endpoint := strings.TrimRight(strings.TrimSuffix(c.Endpoint, "/events"), "/") + "/policy-artifacts/" + url.PathEscape(policyIdentity)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(artifact))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+c.IngestionKey)
	request.Header.Set("X-SECentral-Host-ID", hostID)
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("policy artifact upload failed: HTTP %d", response.StatusCode)
	}
	return nil
}

func (c Client) SendExpectedContextObservation(ctx context.Context, observation protocol.ExpectedContextObservationRequest) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.expectedContextEndpoint(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.IngestionKey)
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests {
			return &PermanentError{Status: response.StatusCode}
		}
		return fmt.Errorf("expected-context observation failed: HTTP %d", response.StatusCode)
	}
	return nil
}

func (c Client) heartbeatEndpoint() string {
	return strings.TrimSuffix(c.Endpoint, "/events") + "/heartbeat"
}

func (c Client) expectedContextEndpoint() string {
	return strings.TrimSuffix(c.Endpoint, "/events") + "/expected-context-observations"
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return http.DefaultClient
	}
	return c.HTTPClient
}

type Result struct {
	Pending                  int
	Delivered                int
	Blocked                  int
	ExpectedContextPending   int
	ExpectedContextDelivered int
	ExpectedContextBlocked   int
	Diagnostics              []error
	GuardedSplits            int
	IsolatedRejections       int
}

type PermanentError struct {
	Status int
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("permanent ingestion failure: HTTP %d", e.Status)
}

func (c Client) SendPending(ctx context.Context, store *spool.Spool) (Result, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	if c.MaxBatchEvents <= 0 {
		c.MaxBatchEvents = DefaultMaxBatchEvents
	}
	var result Result
	var permanentErr error
	for {
		scan, err := store.Pending()
		if err != nil {
			return result, err
		}
		result.Diagnostics = append(result.Diagnostics, scan.Diagnostics...)
		result.Pending = len(scan.Entries)
		if len(scan.Entries) == 0 {
			if permanentErr != nil {
				return result, permanentErr
			}
			if err := c.sendExpectedContextObservations(ctx, store, &result); err != nil {
				return result, err
			}
			return result, nil
		}
		batch := compatibleBatch(scan.Entries, c.MaxBatchEvents)
		before := result.Delivered + result.Blocked
		if err := c.sendBatch(ctx, store, batch, &result, nonBoundaryCohort(batch), len(batch)); err != nil {
			result.Pending -= result.Delivered + result.Blocked - before
			if _, ok := errors.AsType[*PermanentError](err); ok {
				permanentErr = err
				continue
			}
			return result, err
		}
	}
}

func (c Client) sendExpectedContextObservations(ctx context.Context, store *spool.Spool, result *Result) error {
	scan, err := store.ExpectedContextPending()
	if err != nil {
		return err
	}
	result.Diagnostics = append(result.Diagnostics, scan.Diagnostics...)
	result.ExpectedContextPending = len(scan.Entries)
	for _, entry := range scan.Entries {
		err := c.SendExpectedContextObservation(ctx, entry.Item)
		if err == nil {
			if err := store.AckExpectedContextObservation(entry.ID); err != nil {
				return err
			}
			result.ExpectedContextDelivered++
			continue
		}
		if _, ok := errors.AsType[*PermanentError](err); ok {
			if blockErr := store.BlockExpectedContextObservation(entry.ID); blockErr != nil {
				return errors.Join(err, blockErr)
			}
			result.ExpectedContextBlocked++
			continue
		}
		return err
	}
	return nil
}

func compatibleBatch(entries []spool.Entry, limit int) []spool.Entry {
	first := entries[0].Item
	batch := make([]spool.Entry, 0, limit)
	for _, entry := range entries {
		item := entry.Item
		if item.SchemaVersion != first.SchemaVersion || item.Agent != first.Agent || item.HostID != first.HostID || item.BootID != first.BootID || !sameCheckpoint(item.HostObservedAt, first.HostObservedAt) || !slices.Equal(item.CheckpointInvalidatedFields, first.CheckpointInvalidatedFields) {
			continue
		}
		batch = append(batch, entry)
		if len(batch) == limit {
			break
		}
	}
	return batch
}

func sameCheckpoint(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func (c Client) sendBatch(ctx context.Context, store *spool.Spool, entries []spool.Entry, result *Result, originalSafe bool, originalSize int) error {
	request := protocol.IngestRequest{
		SchemaVersion:               entries[0].Item.SchemaVersion,
		Agent:                       entries[0].Item.Agent,
		HostID:                      entries[0].Item.HostID,
		BootID:                      entries[0].Item.BootID,
		HostObservedAt:              entries[0].Item.HostObservedAt,
		CheckpointInvalidatedFields: entries[0].Item.CheckpointInvalidatedFields,
	}
	for _, entry := range entries {
		request.Events = append(request.Events, entry.Item.Event)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+c.IngestionKey)
	response, err := c.HTTPClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusRequestEntityTooLarge {
		if len(entries) == 1 {
			if err := store.Block(entries[0].ID); err != nil {
				return err
			}
			result.Blocked++
			return &PermanentError{Status: response.StatusCode}
		}
		middle := len(entries) / 2
		c.logger().Info("event batch size split", "status", 413, "batch_size", len(entries), "left", middle, "right", len(entries)-middle)
		response.Body.Close()
		return c.sendChildren(ctx, store, entries, result, originalSafe, originalSize)
	}
	if response.StatusCode == http.StatusAccepted {
		for _, entry := range entries {
			if err := store.Ack(entry.ID); err != nil {
				return err
			}
			result.Delivered++
		}
		return nil
	}
	if response.StatusCode == http.StatusUnprocessableEntity {
		data, err := io.ReadAll(io.LimitReader(response.Body, maxValidationResponseBytes+1))
		if err != nil {
			c.logger().Warn("guarded subdivision aborted", "status", 422, "batch_size", len(entries), "reason", "uncertain_response_body")
			return fmt.Errorf("read ingestion rejection: %w", err)
		}
		rejection, eligible := splitEligibleResponse(data, entries)
		if originalSafe && eligible {
			response.Body.Close()
			if len(entries) == 1 {
				entry := entries[0]
				if err := store.BlockWithRejection(entry.ID, rejection); err != nil {
					return err
				}
				result.Blocked++
				result.IsolatedRejections++
				result.Diagnostics = append(result.Diagnostics, fmt.Errorf("event %s quarantined: phase=%s details=%v", entry.ID, rejection.Phase, rejection.Details))
				c.logger().Warn("invalid AVC singleton quarantined", "spool_id", entry.ID, "host_id", entry.Item.HostID, "boot_id", entry.Item.BootID, "audit_event", entry.Item.Event.ID, "evidence_digest", entry.Item.EvidenceDigest, "details", rejection.Details)
				return nil // Fully handled permanent poison; continue primary siblings, then optional work.
			}
			middle := len(entries) / 2
			result.GuardedSplits++
			c.logger().Info("guarded event batch split", "original_batch_size", originalSize, "batch_size", len(entries), "left", middle, "right", len(entries)-middle, "details", rejection.Details)
			return c.sendChildren(ctx, store, entries, result, originalSafe, originalSize)
		}
		c.logger().Warn("guarded subdivision refused", "status", 422, "original_batch_size", originalSize, "batch_size", len(entries), "cohort_proven", originalSafe, "server_proven", eligible)
	}
	if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests {
		for _, entry := range entries {
			if err := store.Block(entry.ID); err != nil {
				return err
			}
			result.Blocked++
		}
		return &PermanentError{Status: response.StatusCode}
	}
	return fmt.Errorf("temporary ingestion failure: HTTP %d", response.StatusCode)
}

// Keep the original proof through both size and poison subdivision. A permanently
// handled child cannot force its unsent sibling to be reclassified as a new cohort.
func (c Client) sendChildren(ctx context.Context, store *spool.Spool, entries []spool.Entry, result *Result, originalSafe bool, originalSize int) error {
	middle := len(entries) / 2
	var permanent error
	for _, child := range [][]spool.Entry{entries[:middle], entries[middle:]} {
		if err := c.sendBatch(ctx, store, child, result, originalSafe, originalSize); err != nil {
			failure, ok := errors.AsType[*PermanentError](err)
			if !ok {
				c.logger().Warn("batch subdivision aborted", "batch_size", len(child), "reason", "retryable_or_local_failure")
				return err
			}
			c.logger().Warn("child subdivision refused", "status", failure.Status, "batch_size", len(child), "reason", "non_eligible_permanent_response")
			permanent = err
		}
	}
	return permanent
}

func (c Client) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func nonBoundaryCohort(entries []spool.Entry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if !audit.ProvablyNonBoundary(entry.Item.Event) {
			return false
		}
	}
	return true
}
