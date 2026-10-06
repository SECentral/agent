//go:build linux

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/delivery"
	"github.com/secentral/agent/metadata"
	"github.com/secentral/agent/protocol"
	"github.com/secentral/agent/spool"
)

var (
	version = "dev"
	commit  = "unknown"
)

type captureStats struct {
	received   atomic.Uint64
	assembled  atomic.Uint64
	spooled    atomic.Uint64
	errors     atomic.Uint64
	enobufs    atomic.Uint64
	mismatches atomic.Uint64
}

const (
	auditReceiveQueueSize  = 2048
	auditEventQueueSize    = 4096
	expectedContextQueue   = 64
	expectedContextKeys    = 1024
	expectedContextTimeout = 2 * time.Second
)

type queuedEvent struct {
	hostID                      string
	bootID                      string
	hostObservedAt              *time.Time
	checkpointInvalidatedFields []string
	event                       audit.Event
}

type observedHost struct {
	metadata                    metadata.HostMetadata
	observedAt                  time.Time
	generation                  uint64
	checkpointInvalidatedFields []string
}

type expectedContextWork struct {
	request protocol.ExpectedContextObservationRequest
	target  audit.ExpectedContextTarget
}

type expectedContextInspector struct {
	ctx        context.Context
	store      *spool.Spool
	version    string
	logger     *slog.Logger
	queue      chan expectedContextWork
	done       chan struct{}
	seen       map[string]struct{}
	checkpoint string
	full       bool
}

func newExpectedContextInspector(ctx context.Context, store *spool.Spool, version string, logger *slog.Logger) *expectedContextInspector {
	inspector := &expectedContextInspector{
		ctx: ctx, store: store, version: version, logger: logger,
		queue: make(chan expectedContextWork, expectedContextQueue),
		done:  make(chan struct{}), seen: make(map[string]struct{}),
	}
	go inspector.run()
	return inspector
}

func (i *expectedContextInspector) enqueue(hostID, bootID string, hostObservedAt *time.Time, event audit.Event) {
	checkpoint := ""
	if hostObservedAt != nil {
		checkpoint = hostObservedAt.UTC().String()
	}
	if checkpoint != i.checkpoint {
		clear(i.seen)
		i.checkpoint = checkpoint
		i.full = false
	}
	eventTargets := make(map[string]struct{})
	for _, target := range audit.ExpectedContextTargets(event) {
		eventKey := strings.Join([]string{target.Path, target.ObjectClass, target.FileType}, "\x00")
		if _, found := eventTargets[eventKey]; found {
			continue
		}
		eventTargets[eventKey] = struct{}{}
		key := strings.Join([]string{
			hostID, bootID, checkpoint, target.Path, target.FileType, target.ObjectClass,
			selinuxType(target.SourceContext), selinuxType(target.TargetContext), strings.Join(target.Permissions, ","),
		}, "\x00")
		if _, found := i.seen[key]; found || i.full {
			continue
		}
		if len(i.seen) >= expectedContextKeys {
			// ponytail: cap deduplication at 1,024 keys per checkpoint; higher cardinality is skipped rather than adding unbounded state.
			i.full = true
			i.logger.Warn("expected-context inspections skipped", "reason", "checkpoint_key_limit")
			return
		}
		request := protocol.ExpectedContextObservationRequest{
			SchemaVersion: protocol.ExpectedContextSchemaVersion,
			Agent:         protocol.AgentMetadata{Version: i.version},
			HostID:        hostID,
			BootID:        bootID,
			AuditEvent: protocol.AuditEventReference{
				Timestamp: event.ID.Timestamp,
				Sequence:  event.ID.Sequence,
			},
			HostObservedAt: hostObservedAt,
			Observation: protocol.ExpectedContextObservation{
				Path:        target.Path,
				ObjectClass: target.ObjectClass,
				FileType:    target.FileType,
				ObservedAt:  time.Now().UTC(),
				Resolver:    "matchpathcon",
				Status:      "unavailable",
				Reason:      target.FileTypeUnavailable,
			},
		}
		if target.FileType != "" {
			request.Observation.Reason = "inspection_pending"
		}
		select {
		case i.queue <- expectedContextWork{request: request, target: target}:
			i.seen[key] = struct{}{}
		default:
			i.seen[key] = struct{}{}
			i.logger.Warn("expected-context inspection skipped", "reason", "work_queue_full", "path", target.Path)
		}
	}
}

func selinuxType(context string) string {
	parts := strings.SplitN(context, ":", 4)
	if len(parts) != 4 {
		return ""
	}
	return parts[2]
}

func (i *expectedContextInspector) run() {
	defer close(i.done)
	for work := range i.queue {
		observation := work.request.Observation
		if work.target.FileType != "" {
			ctx, cancel := context.WithTimeout(i.ctx, expectedContextTimeout)
			result := audit.ResolveExpectedContext(ctx, work.target)
			cancel()
			observation.ExpectedContext = result.Context
			observation.Status = result.Status
			observation.Reason = result.Reason
			observation.ObservedAt = result.At
		}
		work.request.Observation = observation
		if err := i.store.PutExpectedContextObservation(work.request); err != nil {
			i.logger.Warn("expected-context observation not spooled", "error", err, "path", observation.Path)
		}
	}
}

func (i *expectedContextInspector) close() {
	close(i.queue)
	<-i.done
}

func (s *captureStats) log(logger *slog.Logger) {
	logger.Info("audit capture summary", "records_received", s.received.Load(), "events_assembled", s.assembled.Load(), "events_spooled", s.spooled.Load(), "receive_errors", s.errors.Load(), "enobufs_errors", s.enobufs.Load(), "type_payload_mismatches", s.mismatches.Load())
}

func main() {
	endpoint := flag.String("endpoint", os.Getenv("SECENTRAL_ENDPOINT"), "SECentral ingestion endpoint")
	ingestionKey := flag.String("ingestion-key", os.Getenv("SECENTRAL_INGESTION_KEY"), "SECentral ingestion key")
	spoolRoot := flag.String("spool", getenv("SECENTRAL_SPOOL", "/var/lib/secentral/spool"), "agent spool directory")
	interval := flag.Duration("interval", 5*time.Second, "delivery polling interval")
	heartbeatInterval := flag.Duration("heartbeat-interval", 5*time.Minute, "heartbeat interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	replay := flag.String("replay", "", "replay a Protocol v1 JSON request and exit")
	debug := flag.Bool("debug", envBool("SECENTRAL_DEBUG"), "enable structured debug logging")
	flag.Parse()
	if *showVersion {
		fmt.Printf("secentral-agent %s (commit %s)\n", version, commit)
		return
	}
	logger := newLogger(*debug)
	logger.Info("agent starting", "version", version, "commit", commit, "endpoint", *endpoint, "spool", *spoolRoot, "interval", interval.String(), "replay", *replay != "")

	if *endpoint == "" || *ingestionKey == "" {
		fatal(logger, "endpoint and ingestion key are required")
	}
	if *interval <= 0 {
		fatal(logger, "interval must be positive")
	}
	if *heartbeatInterval <= 0 {
		fatal(logger, "heartbeat interval must be positive")
	}
	store, err := spool.New(*spoolRoot, spool.Config{})
	if err != nil {
		fatal(logger, "open spool", err)
	}
	logger.Debug("spool ready")
	client := delivery.Client{Endpoint: *endpoint, IngestionKey: *ingestionKey}
	if *replay != "" {
		if err := replayRequest(*replay, version, store); err != nil {
			fatal(logger, "replay request", err)
		}
		logger.Debug("replay request spooled", "path", *replay)
		result, err := client.SendPending(context.Background(), store)
		for _, diagnostic := range result.Diagnostics {
			logger.Warn("spool diagnostic", "error", diagnostic)
		}
		if err != nil {
			fatal(logger, "replay delivery", err)
		}
		logger.Info("replay delivered", "delivered", result.Delivered, "blocked", result.Blocked)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, client, store, *interval, *heartbeatInterval, version, logger); err != nil {
		fatal(logger, "agent stopped", err)
	}
}

func run(ctx context.Context, client delivery.Client, store *spool.Spool, interval, heartbeatInterval time.Duration, agentVersion string, logger *slog.Logger) error {
	identity, err := metadata.CollectIdentity("/")
	if err != nil {
		return fmt.Errorf("collect host identity: %w", err)
	}
	hostState := &atomic.Pointer[observedHost]{}
	hostState.Store(&observedHost{metadata: identity})
	refreshRequests := make(chan struct{}, 1)
	stats := &captureStats{}
	defer stats.log(logger)
	runCtx, cancel := context.WithCancel(ctx)
	eventQueue := make(chan queuedEvent, auditEventQueueSize)
	expectedInspector := newExpectedContextInspector(runCtx, store, agentVersion, logger)
	eventDone := make(chan struct{})
	go func() {
		defer close(eventDone)
		for queued := range eventQueue {
			if err := putEvent(store, queued.hostID, queued.bootID, queued.hostObservedAt, queued.checkpointInvalidatedFields, agentVersion, queued.event); err != nil {
				logger.Error("spool write failed", "error", err)
				continue
			}
			stats.spooled.Add(1)
			expectedInspector.enqueue(queued.hostID, queued.bootID, queued.hostObservedAt, queued.event)
		}
	}()
	defer func() {
		cancel()
		close(eventQueue)
		<-eventDone
		expectedInspector.close()
	}()
	enqueueEvent := func(event audit.Event) {
		stats.assembled.Add(1)
		host := hostState.Load()
		var checkpoint *time.Time
		if !host.observedAt.IsZero() {
			checkpoint = new(host.observedAt)
		}
		eventQueue <- queuedEvent{hostID: host.metadata.ID, bootID: host.metadata.BootID, hostObservedAt: checkpoint, checkpointInvalidatedFields: host.checkpointInvalidatedFields, event: event}
	}
	go runHeartbeatLoop(runCtx, client, hostState, refreshRequests, heartbeatInterval, agentVersion, logger)
	go runDeliveryLoop(runCtx, client, store, interval, logger)
	assembler := audit.NewAssembler(audit.DefaultConfig())
	auditClient, err := libaudit.NewMulticastAuditClient(nil)
	if err != nil {
		return err
	}
	defer auditClient.Close()

	type received struct {
		message *libaudit.RawAuditMessage
		err     error
	}
	messages := make(chan received, auditReceiveQueueSize)
	go func() {
		for {
			message, err := auditClient.Receive(false)
			if message != nil {
				message = copyRawAuditMessage(message)
			}
			select {
			case messages <- received{message: message, err: err}:
			case <-runCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-runCtx.Done():
			logger.Debug("shutdown requested")
			for _, event := range assembler.Close() {
				enqueueEvent(event)
			}
			return nil
		case result := <-messages:
			if result.err != nil {
				stats.errors.Add(1)
				if errors.Is(result.err, syscall.ENOBUFS) {
					stats.enobufs.Add(1)
					logger.Error("audit receive buffer exhausted", "error", result.err)
				} else {
					logger.Error("audit receive failed", "error", result.err)
				}
				return result.err
			}
			stats.received.Add(1)
			if audit.SuccessfulStateTransitionRecord(result.message) {
				// Invalidate on receipt, not event completion, so a timeout cannot
				// let a later AVC inherit the pre-transition state checkpoint.
				policyChanged := result.message.Type != auparse.AUDIT_MAC_STATUS
				fields := []string{"enforcement"}
				if result.message.Type == auparse.AUDIT_USER_MAC_CONFIG_CHANGE {
					fields = []string{"ports", "policy_identity"}
				}
				unknown := invalidateHostState(hostState, policyChanged && result.message.Type != auparse.AUDIT_USER_MAC_CONFIG_CHANGE, fields...)
				logger.Info("SELinux state boundary observed", "record_type", result.message.Type.String(), "agent_received_at", time.Now().UTC(), "state_generation", unknown.generation, "policy_invalidated", policyChanged, "checkpoint_invalidated_fields", unknown.checkpointInvalidatedFields)
				requestPolicyRefresh(refreshRequests)
			}
			if auditRecordTypeMismatch(result.message) {
				stats.mismatches.Add(1)
			}
			for _, event := range push(assembler, result.message, logger) {
				enqueueEvent(event)
			}
		case now := <-ticker.C:
			for _, event := range assembler.Maintain(now) {
				enqueueEvent(event)
			}
		}
	}
}

func runHeartbeatLoop(ctx context.Context, client delivery.Client, state *atomic.Pointer[observedHost], refreshRequests <-chan struct{}, interval time.Duration, version string, logger *slog.Logger) {
	backoff := interval
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := refreshHostState(ctx, client, state, version, logger); err != nil {
				backoff = min(backoff*2, 5*time.Minute)
			} else {
				backoff = interval
			}
			timer.Reset(backoff)
		case <-refreshRequests:
			logger.Info("refreshing host state after SELinux transition", "policy_generation", state.Load().generation)
			if err := refreshHostState(ctx, client, state, version, logger); err != nil {
				backoff = min(backoff*2, 5*time.Minute)
			} else {
				backoff = interval
			}
			timer.Reset(backoff)
		}
	}
}

func refreshHostState(ctx context.Context, client delivery.Client, state *atomic.Pointer[observedHost], version string, logger *slog.Logger) error {
	previous := state.Load()
	next := collectMetadata(previous.metadata, logger)
	host, published := publishHostState(state, previous, next)
	if !published {
		logger.Debug("discarding stale host-state refresh", "refresh_generation", previous.generation, "current_generation", state.Load().generation)
		return nil
	}
	if err := sendHeartbeat(ctx, client, *host, version, logger); err != nil {
		return err
	}
	return nil
}

func publishHostState(state *atomic.Pointer[observedHost], previous *observedHost, next observedHost) (*observedHost, bool) {
	next.generation = previous.generation
	updated := &next
	return updated, state.CompareAndSwap(previous, updated)
}

func invalidateHostState(state *atomic.Pointer[observedHost], policyChanged bool, fields ...string) *observedHost {
	for {
		previous := state.Load()
		next := *previous
		next.generation++
		if policyChanged {
			next.metadata.SELinux.PolicyIdentity = ""
			next.metadata.SELinux.BooleanStatus = "unknown"
			next.metadata.SELinux.Booleans = nil
			next.observedAt = time.Time{}
			next.checkpointInvalidatedFields = nil
		} else {
			if len(fields) == 0 {
				fields = []string{"enforcement"}
			}
			next.checkpointInvalidatedFields = slices.Clone(previous.checkpointInvalidatedFields)
			for _, field := range fields {
				if !slices.Contains(next.checkpointInvalidatedFields, field) {
					next.checkpointInvalidatedFields = append(next.checkpointInvalidatedFields, field)
				}
				switch field {
				case "enforcement":
					next.metadata.SELinux.Enforcement = metadata.Unknown
				case "policy_identity":
					next.metadata.SELinux.PolicyIdentity = ""
				case "ports":
					next.metadata.SELinux.Policy.PortInventory = &metadata.PortInventory{Status: "unknown"}
				}
			}
			slices.Sort(next.checkpointInvalidatedFields)
		}
		if state.CompareAndSwap(previous, &next) {
			return &next
		}
	}
}

func requestPolicyRefresh(requests chan struct{}) {
	select {
	case requests <- struct{}{}:
	default:
		select {
		case <-requests:
		default:
		}
		requests <- struct{}{}
	}
}

func runDeliveryLoop(ctx context.Context, client delivery.Client, store *spool.Spool, interval time.Duration, logger *slog.Logger) {
	backoff := interval
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			result, err := client.SendPending(ctx, store)
			for _, diagnostic := range result.Diagnostics {
				logger.Warn("spool diagnostic", "error", diagnostic)
			}
			if result.ExpectedContextBlocked > 0 {
				logger.Warn("expected-context observations blocked", "count", result.ExpectedContextBlocked)
			}
			logger.Debug("delivery poll", "pending", result.Pending, "delivered", result.Delivered, "blocked", result.Blocked, "expected_context_pending", result.ExpectedContextPending, "expected_context_delivered", result.ExpectedContextDelivered)
			if err != nil {
				logger.Warn("delivery failed", "error", err)
				if _, ok := errors.AsType[*delivery.PermanentError](err); ok {
					backoff = interval
				} else {
					backoff = min(backoff*2, 5*time.Minute)
				}
			} else {
				backoff = interval
			}
			timer.Reset(backoff)
		}
	}
}

func collectMetadata(previous metadata.HostMetadata, logger *slog.Logger) observedHost {
	host, diagnostics := metadata.Collect("/")
	if host.SELinux.Policy.Package == nil && previous.SELinux.Policy.Package != nil {
		host.SELinux.Policy.Package = previous.SELinux.Policy.Package
	}
	if host.SELinux.Policy.Modules == nil && previous.SELinux.Policy.Modules != nil {
		host.SELinux.Policy.Modules = previous.SELinux.Policy.Modules
	}
	if host.SELinux.Policy.CustomModules == nil && previous.SELinux.Policy.CustomModules != nil {
		host.SELinux.Policy.CustomModules = previous.SELinux.Policy.CustomModules
	}
	if diagnostics != nil {
		logger.Warn("metadata collection incomplete", "error", diagnostics)
	}
	// A checkpoint is not available at collection start. Dating it at completion
	// prevents later replay from backfilling AVCs captured during collection.
	return observedHost{metadata: host, observedAt: time.Now().UTC()}
}

func sendHeartbeat(ctx context.Context, client delivery.Client, host observedHost, version string, logger *slog.Logger) error {
	heartbeatCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.SendHeartbeat(heartbeatCtx, host.metadata, host.observedAt, version)
	if err != nil {
		logger.Warn("heartbeat failed", "error", err)
		return err
	}
	if response.PolicyArtifactRequired {
		artifact, identity, err := metadata.ReadPolicyArtifact("/")
		if err == nil && identity != response.PolicyIdentity {
			err = fmt.Errorf("loaded policy changed during artifact acquisition: heartbeat=%s current=%s", response.PolicyIdentity, identity)
		}
		if err == nil {
			uploadCtx, uploadCancel := context.WithTimeout(ctx, 30*time.Second)
			err = uploadPolicyArtifactIfIdentityMatches(uploadCtx, client, host.metadata.ID, response.PolicyIdentity, identity, artifact)
			uploadCancel()
		}
		if err != nil {
			logger.Warn("policy artifact upload failed; evidence capture continues", "policy_identity", response.PolicyIdentity, "error", err)
		}
	}
	logger.Debug("heartbeat sent", "policy_identity", host.metadata.SELinux.PolicyIdentity, "host_observed_at", host.observedAt)
	return nil
}

func uploadPolicyArtifactIfIdentityMatches(ctx context.Context, client delivery.Client, hostID, requestedIdentity, actualIdentity string, artifact []byte) error {
	if actualIdentity != requestedIdentity {
		return fmt.Errorf("loaded policy changed during artifact acquisition: heartbeat=%s current=%s", requestedIdentity, actualIdentity)
	}
	return client.UploadPolicyArtifact(ctx, hostID, actualIdentity, artifact)
}

func copyRawAuditMessage(message *libaudit.RawAuditMessage) *libaudit.RawAuditMessage {
	if message == nil {
		return nil
	}
	return &libaudit.RawAuditMessage{Type: message.Type, Data: bytes.Clone(message.Data)}
}

func push(assembler *audit.Assembler, message *libaudit.RawAuditMessage, logger *slog.Logger) []audit.Event {
	if auditRecordTypeMismatch(message) {
		logger.Warn("audit record type/payload mismatch", "type", message.Type.String(), "bytes", len(message.Data), "payload_sha256", auditPayloadDigest(message.Data))
	}
	events, err := assembler.PushOwned(message, time.Now())
	if err != nil {
		logger.Warn("audit record rejected", "error", err)
		return nil
	}
	return events
}

func auditRecordTypeMismatch(message *libaudit.RawAuditMessage) bool {
	if message == nil {
		return false
	}
	switch message.Type {
	case auparse.AUDIT_AVC:
		return !bytes.Contains(message.Data, []byte(" avc:"))
	case auparse.AUDIT_USER_AVC:
		return !bytes.Contains(message.Data, []byte(" user_avc:"))
	case auparse.AUDIT_EOE:
		return !bytes.Contains(message.Data, []byte("audit("))
	default:
		return false
	}
}

func auditPayloadDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func putEvent(store *spool.Spool, hostID, bootID string, hostObservedAt *time.Time, invalidatedFields []string, agentVersion string, event audit.Event) error {
	err := store.Put(spool.Item{
		SchemaVersion:               protocol.SchemaVersion,
		Agent:                       protocol.AgentMetadata{Version: agentVersion},
		HostID:                      hostID,
		BootID:                      bootID,
		HostObservedAt:              hostObservedAt,
		CheckpointInvalidatedFields: invalidatedFields,
		Event:                       event,
	})
	return err
}

func replayRequest(path, agentVersion string, store *spool.Spool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var request protocol.IngestRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return err
	}
	if request.Agent.Version == "" {
		request.Agent.Version = agentVersion
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("invalid replay request: %w", err)
	}
	for _, event := range request.Events {
		if err := store.Put(spool.Item{SchemaVersion: request.SchemaVersion, Agent: request.Agent, HostID: request.HostID, BootID: request.BootID, HostObservedAt: request.HostObservedAt, CheckpointInvalidatedFields: request.CheckpointInvalidatedFields, Event: event}); err != nil {
			return err
		}
	}
	return nil
}

func newLogger(debug bool) *slog.Logger {
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	if debug {
		level.Set(slog.LevelDebug)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func envBool(key string) bool {
	return strings.EqualFold(os.Getenv(key), "true")
}

func fatal(logger *slog.Logger, message string, args ...any) {
	if len(args) == 1 {
		logger.Error(message, "error", args[0])
	} else {
		logger.Error(message)
	}
	os.Exit(1)
}

func getenv(key, fallback string) string {
	return cmp.Or(os.Getenv(key), fallback)
}
