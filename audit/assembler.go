package audit

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

type AuditEventID struct {
	Timestamp time.Time `json:"timestamp"`
	Sequence  uint32    `json:"sequence"`
}

type CompletionReason string

const (
	CompletionEOE      CompletionReason = "eoe"
	CompletionTimeout  CompletionReason = "timeout"
	CompletionCapacity CompletionReason = "capacity"
	CompletionShutdown CompletionReason = "shutdown"
)

type Record struct {
	Position  int                      `json:"position"`
	Type      auparse.AuditMessageType `json:"type"`
	TypeName  string                   `json:"type_name"`
	Timestamp time.Time                `json:"timestamp"`
	Sequence  uint32                   `json:"sequence"`
	Raw       []byte                   `json:"payload"`
}

type Event struct {
	Category        Category         `json:"category"`
	ID              AuditEventID     `json:"audit_event"`
	AgentReceivedAt time.Time        `json:"agent_received_at"`
	Records         []Record         `json:"records"`
	Completion      CompletionReason `json:"completion_reason"`
}

type Category string

const (
	CategoryAVC                   Category = "avc"
	CategorySELinuxAdministrative Category = "selinux_administrative"
)

type Config struct {
	Timeout       time.Duration
	MaxInFlight   int
	LateRecordTTL time.Duration
}

func DefaultConfig() Config {
	return Config{Timeout: 2 * time.Second, MaxInFlight: 1024, LateRecordTTL: 2 * time.Second}
}

type Assembler struct {
	config         Config
	events         map[AuditEventID]*pendingEvent
	completed      map[AuditEventID]completedEvent
	completedOrder []AuditEventID
	late           uint64
	nextOrder      uint64
}

type completedEvent struct {
	expiresAt time.Time
}

type pendingEvent struct {
	event   Event
	created time.Time
	order   uint64
}

func NewAssembler(config Config) *Assembler {
	if config.Timeout <= 0 {
		config.Timeout = DefaultConfig().Timeout
	}
	if config.MaxInFlight <= 0 {
		config.MaxInFlight = DefaultConfig().MaxInFlight
	}
	if config.LateRecordTTL <= 0 {
		config.LateRecordTTL = config.Timeout
	}
	return &Assembler{
		config:    config,
		events:    make(map[AuditEventID]*pendingEvent),
		completed: make(map[AuditEventID]completedEvent),
	}
}

func (a *Assembler) Push(message *libaudit.RawAuditMessage, now time.Time) ([]Event, error) {
	return a.push(message, bytes.Clone(message.Data), now)
}

// PushOwned takes ownership of message.Data; the caller must not mutate it.
func (a *Assembler) PushOwned(message *libaudit.RawAuditMessage, now time.Time) ([]Event, error) {
	return a.push(message, message.Data, now)
}

func (a *Assembler) push(message *libaudit.RawAuditMessage, raw []byte, now time.Time) ([]Event, error) {
	a.pruneCompleted(now)
	timestamp, sequence, err := parseAuditIdentity(raw)
	if err != nil {
		return nil, err
	}

	id := AuditEventID{Timestamp: timestamp, Sequence: sequence}
	if _, found := a.completed[id]; found {
		a.late++
		return nil, nil
	}

	pending, found := a.events[id]
	if !found {
		pending = &pendingEvent{
			event:   Event{ID: id, AgentReceivedAt: now},
			created: now,
			order:   a.nextOrder,
		}
		a.nextOrder++
		a.events[id] = pending
	}
	pending.event.Records = append(pending.event.Records, Record{
		Position:  len(pending.event.Records),
		Type:      message.Type,
		TypeName:  message.Type.String(),
		Timestamp: timestamp,
		Sequence:  sequence,
		Raw:       raw,
	})

	if message.Type == auparse.AUDIT_EOE {
		event, relevant := a.finish(id, CompletionEOE, now)
		if relevant {
			return []Event{event}, nil
		}
		return nil, nil
	}
	return a.evict(now), nil
}

func parseAuditIdentity(raw []byte) (time.Time, uint32, error) {
	const marker = "audit("
	start := bytes.Index(raw, []byte(marker))
	if start < 0 {
		return time.Time{}, 0, fmt.Errorf("audit identity missing")
	}
	start += len(marker)
	end := bytes.Index(raw[start:], []byte("):"))
	if end < 0 {
		return time.Time{}, 0, fmt.Errorf("audit identity malformed")
	}
	timestampText, sequenceText, ok := strings.Cut(string(raw[start:start+end]), ":")
	if !ok {
		return time.Time{}, 0, fmt.Errorf("audit sequence missing")
	}
	secondsText, fraction, hasFraction := strings.Cut(timestampText, ".")
	seconds, err := strconv.ParseInt(secondsText, 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("audit seconds: %w", err)
	}
	var nanoseconds int64
	if hasFraction {
		if fraction == "" || len(fraction) > 9 {
			return time.Time{}, 0, fmt.Errorf("audit timestamp fraction malformed")
		}
		fraction += strings.Repeat("0", 9-len(fraction))
		nanoseconds, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("audit fraction: %w", err)
		}
	}
	sequence, err := strconv.ParseUint(sequenceText, 10, 32)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("audit sequence: %w", err)
	}
	return time.Unix(seconds, nanoseconds).UTC(), uint32(sequence), nil
}

func SuccessfulPolicyLoadRecord(message *libaudit.RawAuditMessage) bool {
	if message == nil || message.Type != auparse.AUDIT_MAC_POLICY_LOAD {
		return false
	}
	for field := range strings.FieldsSeq(string(message.Data)) {
		if field == "res=1" {
			return true
		}
	}
	return false
}

var booleanName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// BooleanChangeFields recognizes only the kernel runtime-boolean record shape.
// The tested kernel emits no res: it logs changed booleans after failure checks,
// immediately before publishing the updated policy. An explicit failure wins.
func BooleanChangeFields(message *libaudit.RawAuditMessage) map[string]string {
	if message == nil || message.Type != auparse.AUDIT_MAC_CONFIG_CHANGE {
		return nil
	}
	fields := make(map[string]string)
	for field := range strings.FieldsSeq(string(message.Data)) {
		key, value, _ := strings.Cut(field, "=")
		if key != "bool" && key != "val" && key != "old_val" && key != "res" {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return nil
		}
		fields[key] = value
	}
	if !booleanName.MatchString(fields["bool"]) ||
		(fields["val"] != "0" && fields["val"] != "1") ||
		(fields["old_val"] != "0" && fields["old_val"] != "1") {
		return nil
	}
	return fields
}

func SuccessfulStateTransitionRecord(message *libaudit.RawAuditMessage) bool {
	if SuccessfulPolicyLoadRecord(message) || SuccessfulEnforcementChangeRecord(message) || SuccessfulPortChangeRecord(message) {
		return true
	}
	fields := BooleanChangeFields(message)
	result, explicit := fields["res"]
	return fields != nil && fields["val"] != fields["old_val"] && (!explicit || result == "1")
}

// EnforcementChangeFields recognizes the tested enabled SELinux runtime shape.
// The kernel logs this after permission checks but before enforcing_set; a
// successful record ends old-mode trust without measuring publication time.
func EnforcementChangeFields(message *libaudit.RawAuditMessage) map[string]string {
	if message == nil || message.Type != auparse.AUDIT_MAC_STATUS {
		return nil
	}
	fields := make(map[string]string)
	for field := range strings.FieldsSeq(string(message.Data)) {
		key, value, _ := strings.Cut(field, "=")
		switch key {
		case "enforcing", "old_enforcing", "enabled", "old-enabled", "lsm", "res", "old_enabled", "success", "operation":
			if _, duplicate := fields[key]; duplicate {
				return nil
			}
			fields[key] = value
		}
	}
	for _, key := range []string{"enforcing", "old_enforcing"} {
		if fields[key] != "0" && fields[key] != "1" {
			return nil
		}
	}
	if fields["enabled"] != "1" || fields["old-enabled"] != "1" || fields["lsm"] != "selinux" {
		return nil
	}
	for _, key := range []string{"old_enabled", "success", "operation"} {
		if _, unvalidated := fields[key]; unvalidated {
			return nil
		}
	}
	return fields
}

func SuccessfulEnforcementChangeRecord(message *libaudit.RawAuditMessage) bool {
	fields := EnforcementChangeFields(message)
	return fields != nil && fields["res"] == "1" && fields["enforcing"] != fields["old_enforcing"]
}

var userChangeMessage = regexp.MustCompile(`(?:^|\s)msg='([^']*)'(?:\s|$)`)
var userChangeField = regexp.MustCompile(`(?:^|\s)([A-Za-z_]+)=("(?:\\.|[^"])*"|[^\s"]*)`)
var userChangeBody = regexp.MustCompile(`^(?:[A-Za-z_]+=(?:"(?:\\.|[^"])*"|[^\s"]*)(?:\s+|$))+$`)
var portNumber = regexp.MustCompile(`^[0-9]+(?:-[0-9]+)?$`)
var portContext = regexp.MustCompile(`^system_u:object_r:[A-Za-z_][A-Za-z0-9_]*:s0$`)

// PortChangeFields supports only the observed libsemanage port write shape.
// Delete omits context; modify supplies no old value, even for equal-value writes.
func PortChangeFields(message *libaudit.RawAuditMessage) map[string]string {
	if message == nil || message.Type != auparse.AUDIT_USER_MAC_CONFIG_CHANGE {
		return nil
	}
	matches := userChangeMessage.FindAllStringSubmatch(string(message.Data), -1)
	if len(matches) != 1 || !userChangeBody.MatchString(matches[0][1]) {
		return nil
	}
	fields := make(map[string]string)
	for _, field := range userChangeField.FindAllStringSubmatch(matches[0][1], -1) {
		key, value := field[1], field[2]
		switch key {
		case "resrc", "op", "lport", "proto", "tcontext", "res", "success", "old_tcontext", "old_type":
			if _, duplicate := fields[key]; duplicate {
				return nil
			}
			fields[key] = value
		}
	}
	if fields["resrc"] != "port" || (fields["op"] != "add" && fields["op"] != "modify" && fields["op"] != "delete") ||
		(fields["proto"] != "6" && fields["proto"] != "17") || !portNumber.MatchString(fields["lport"]) {
		return nil
	}
	low, high, ranged := strings.Cut(fields["lport"], "-")
	if !ranged {
		high = low
	}
	start, err := strconv.ParseUint(low, 10, 16)
	end, endErr := strconv.ParseUint(high, 10, 16)
	if err != nil || endErr != nil || start == 0 || end < start {
		return nil
	}
	if fields["op"] == "delete" {
		if _, present := fields["tcontext"]; present {
			return nil
		}
	} else if !portContext.MatchString(fields["tcontext"]) {
		return nil
	}
	for _, key := range []string{"success", "old_tcontext", "old_type"} {
		if _, present := fields[key]; present {
			return nil
		}
	}
	return fields
}

func SuccessfulPortChangeRecord(message *libaudit.RawAuditMessage) bool {
	fields := PortChangeFields(message)
	return fields != nil && fields["res"] == "success"
}

// Retain malformed/failed port history, without collecting unrelated semanage families.
func PortChangeRecord(message *libaudit.RawAuditMessage) bool {
	if message == nil || message.Type != auparse.AUDIT_USER_MAC_CONFIG_CHANGE {
		return false
	}
	matches := userChangeMessage.FindAllStringSubmatch(string(message.Data), -1)
	for _, match := range matches {
		if match[1] == "resrc=port" || strings.HasPrefix(match[1], "resrc=port ") {
			return true
		}
	}
	return false
}

func (a *Assembler) Maintain(now time.Time) []Event {
	a.pruneCompleted(now)
	return a.evict(now)
}

func (a *Assembler) Close() []Event {
	var finished []Event
	for len(a.events) > 0 {
		id := oldest(a.events)
		if event, ok := a.finish(id, CompletionShutdown, time.Now()); ok {
			finished = append(finished, event)
		}
	}
	return finished
}

func (a *Assembler) LateRecords() uint64 {
	return a.late
}

func (a *Assembler) finish(id AuditEventID, reason CompletionReason, now time.Time) (Event, bool) {
	pending, found := a.events[id]
	if !found {
		return Event{}, false
	}
	delete(a.events, id)
	a.completed[id] = completedEvent{expiresAt: now.Add(a.config.LateRecordTTL)}
	a.completedOrder = append(a.completedOrder, id)
	a.pruneCompleted(now)
	pending.event.Completion = reason
	category, ok := eventCategory(pending.event.Records)
	if !ok {
		return Event{}, false
	}
	pending.event.Category = category
	return pending.event, true
}

func (a *Assembler) evict(now time.Time) []Event {
	var finished []Event
	for len(a.events) > a.config.MaxInFlight {
		if event, ok := a.finish(oldest(a.events), CompletionCapacity, now); ok {
			finished = append(finished, event)
		}
	}
	for id, pending := range a.events {
		if now.Before(pending.created.Add(a.config.Timeout)) {
			continue
		}
		if event, ok := a.finish(id, CompletionTimeout, now); ok {
			finished = append(finished, event)
		}
	}
	return finished
}

func (a *Assembler) pruneCompleted(now time.Time) {
	for id, completed := range a.completed {
		if !now.Before(completed.expiresAt) {
			delete(a.completed, id)
		}
	}
	for len(a.completed) > a.config.MaxInFlight && len(a.completedOrder) > 0 {
		id := a.completedOrder[0]
		a.completedOrder = a.completedOrder[1:]
		delete(a.completed, id)
	}
	for len(a.completedOrder) > 0 {
		if _, found := a.completed[a.completedOrder[0]]; found {
			break
		}
		a.completedOrder = a.completedOrder[1:]
	}
}

func oldest(events map[AuditEventID]*pendingEvent) AuditEventID {
	var oldestID AuditEventID
	var oldestEvent *pendingEvent
	for id, event := range events {
		if oldestEvent == nil || event.created.Before(oldestEvent.created) ||
			(event.created.Equal(oldestEvent.created) && event.order < oldestEvent.order) {
			oldestID, oldestEvent = id, event
		}
	}
	return oldestID
}

func eventCategory(records []Record) (Category, bool) {
	for _, record := range records {
		if record.Type == auparse.AUDIT_AVC || record.Type == auparse.AUDIT_USER_AVC {
			return CategoryAVC, true
		}
	}
	for _, record := range records {
		if record.Type == auparse.AUDIT_MAC_POLICY_LOAD || record.Type == auparse.AUDIT_MAC_STATUS || BooleanChangeFields(&libaudit.RawAuditMessage{Type: record.Type, Data: record.Raw}) != nil || PortChangeRecord(&libaudit.RawAuditMessage{Type: record.Type, Data: record.Raw}) {
			return CategorySELinuxAdministrative, true
		}
	}
	return "", false
}
