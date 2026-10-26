package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestParseAuditIdentity(t *testing.T) {
	for _, test := range []struct {
		value string
		want  time.Time
	}{
		{value: "audit(100:7):", want: time.Unix(100, 0).UTC()},
		{value: "type=AVC msg=audit(100.123456:7):", want: time.Unix(100, 123456000).UTC()},
	} {
		got, sequence, err := parseAuditIdentity([]byte(test.value))
		if err != nil || !got.Equal(test.want) || sequence != 7 {
			t.Fatalf("parseAuditIdentity(%q) = %v, %d, %v", test.value, got, sequence, err)
		}
	}
	if _, _, err := parseAuditIdentity([]byte("no audit identity")); err == nil {
		t.Fatal("expected malformed audit identity to fail")
	}
}

func TestAssemblerGroupsInterleavedRecordsByTimestampAndSequence(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{Timeout: time.Second, MaxInFlight: 10})

	push := func(typ auparse.AuditMessageType, raw string) []Event {
		events, err := a.Push(&libaudit.RawAuditMessage{Type: typ, Data: []byte(raw)}, now)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}

	push(auparse.AUDIT_AVC, "audit(100.000:7): avc:  denied  { read } for  pid=10")
	push(auparse.AUDIT_SYSCALL, "audit(100.000:8): arch=c000003e syscall=0 success=no")
	push(auparse.AUDIT_SYSCALL, "audit(100.000:7): arch=c000003e syscall=2 success=no")
	push(auparse.AUDIT_PATH, "audit(100.000:7): name=\"/tmp/x\"")
	events := push(auparse.AUDIT_EOE, "audit(100.000:7):")

	if len(events) != 1 || events[0].ID.Sequence != 7 {
		t.Fatalf("got %#v", events)
	}
	if len(events[0].Records) != 4 {
		t.Fatalf("got %d records", len(events[0].Records))
	}
	if events[0].Category != CategoryAVC {
		t.Fatalf("got category %q", events[0].Category)
	}
	if events[0].Completion != CompletionEOE {
		t.Fatalf("got completion %q", events[0].Completion)
	}
}

func TestAssemblerDoesNotMixSameSequenceAcrossTimestamps(t *testing.T) {
	a := NewAssembler(Config{Timeout: time.Second, MaxInFlight: 10})
	first := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:7): avc: denied")}
	second := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(101.000:7): avc: denied")}
	if _, err := a.Push(first, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Push(second, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	events := a.Close()
	if len(events) != 2 || !events[0].ID.Timestamp.Before(events[1].ID.Timestamp) {
		t.Fatalf("got %#v", events)
	}
}

func TestAssemblerPreservesRawBytesAndSupportsTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{Timeout: time.Second, MaxInFlight: 10})
	raw := []byte("audit(100.000:7): avc:  denied  { read } for  pid=10 \xff")
	message := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: raw}
	if _, err := a.Push(message, now); err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X'
	events := a.Maintain(now.Add(2 * time.Second))
	if len(events) != 1 || events[0].Completion != CompletionTimeout {
		t.Fatalf("got %#v", events)
	}
	if !bytes.Equal(events[0].Records[0].Raw, []byte("audit(100.000:7): avc:  denied  { read } for  pid=10 \xff")) {
		t.Fatal("raw record was not copied")
	}
}

func TestAssemblerRelevanceAndLateRecords(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{Timeout: time.Second, MaxInFlight: 10})
	path := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC_PATH, Data: []byte("audit(100.000:7):")}
	if events, err := a.Push(path, now); err != nil || len(events) != 0 {
		t.Fatalf("standalone AVC_PATH: events=%v err=%v", events, err)
	}
	avc := &libaudit.RawAuditMessage{Type: auparse.AUDIT_USER_AVC, Data: []byte("audit(100.000:7): msg=denied")}
	events, err := a.Push(avc, now)
	if err != nil {
		t.Fatal(err)
	}
	if events = a.Close(); len(events) != 1 || events[0].Completion != CompletionShutdown {
		t.Fatalf("got %#v", events)
	}
	if _, err = a.Push(avc, now); err != nil {
		t.Fatal(err)
	}
	if a.LateRecords() != 1 {
		t.Fatalf("got %d late records", a.LateRecords())
	}
}

func TestAssemblerRetainsPolicyLoadAsAdministrativeEvidence(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(DefaultConfig())
	records := []struct {
		typeID  auparse.AuditMessageType
		payload string
	}{
		{auparse.AUDIT_MAC_POLICY_LOAD, "audit(100.000:7): auid=4294967295 res=1"},
		{auparse.AUDIT_SYSCALL, "audit(100.000:7): success=yes comm=\"load_policy\""},
		{auparse.AUDIT_PROCTITLE, "audit(100.000:7): proctitle=2F7362696E2F6C6F61645F706F6C696379"},
	}
	for _, record := range records {
		if _, err := a.Push(&libaudit.RawAuditMessage{Type: record.typeID, Data: []byte(record.payload)}, now); err != nil {
			t.Fatal(err)
		}
	}
	events, err := a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_EOE, Data: []byte("audit(100.000:7):")}, now)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	event := events[0]
	if event.Category != CategorySELinuxAdministrative || len(event.Records) != 4 || event.ID.Sequence != 7 {
		t.Fatalf("administrative evidence not reconstructed: %#v", event)
	}
	for i, record := range event.Records {
		if string(record.Raw) == "" || record.Position != i {
			t.Fatalf("record %d was not preserved: %#v", i, record)
		}
	}
}

func TestSuccessfulPolicyLoadRequiresExplicitSuccess(t *testing.T) {
	for _, test := range []struct {
		name    string
		typeID  auparse.AuditMessageType
		payload string
		want    bool
	}{
		{name: "success", typeID: auparse.AUDIT_MAC_POLICY_LOAD, payload: "audit(100.000:7): res=1", want: true},
		{name: "failure", typeID: auparse.AUDIT_MAC_POLICY_LOAD, payload: "audit(100.000:7): res=0"},
		{name: "other record", typeID: auparse.AUDIT_SYSCALL, payload: "audit(100.000:7): res=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := &libaudit.RawAuditMessage{Type: test.typeID, Data: []byte(test.payload)}
			if got := SuccessfulPolicyLoadRecord(message); got != test.want {
				t.Fatalf("SuccessfulPolicyLoadRecord() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestBooleanTransitionRecognitionAndRetention(t *testing.T) {
	for _, test := range []struct {
		name, fields         string
		retained, transition bool
	}{
		{"forward kernel commit", "bool=httpd_can_network_connect val=0 old_val=1 auid=0 ses=535", true, true},
		{"reverse kernel commit", "bool=httpd_can_network_connect val=1 old_val=0", true, true},
		{"explicit success", "bool=httpd_can_network_connect val=0 old_val=1 res=1", true, true},
		{"failed attempt", "bool=httpd_can_network_connect val=0 old_val=1 res=0", true, false},
		{"unknown result", "bool=httpd_can_network_connect val=0 old_val=1 res=unknown", true, false},
		{"malformed result", "bool=httpd_can_network_connect val=0 old_val=1 res", true, false},
		{"no change", "bool=httpd_can_network_connect val=1 old_val=1", true, false},
		{"missing old value", "bool=httpd_can_network_connect val=0", false, false},
		{"invalid value", "bool=httpd_can_network_connect val=2 old_val=1", false, false},
		{"duplicate field", "bool=httpd_can_network_connect val=0 old_val=1 res=0 res=1", false, false},
		{"other config", "op=unrelated res=1", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := &libaudit.RawAuditMessage{Type: auparse.AUDIT_MAC_CONFIG_CHANGE, Data: []byte("audit(1790851328.281:50361): " + test.fields)}
			if got := SuccessfulStateTransitionRecord(message); got != test.transition {
				t.Fatalf("transition = %t, want %t", got, test.transition)
			}
			a := NewAssembler(DefaultConfig())
			now := time.Unix(1790851328, 281000000)
			a.Push(message, now)
			a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_SYSCALL, Data: []byte("audit(1790851328.281:50361): success=yes comm=\"setsebool\"")}, now)
			events, err := a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_EOE, Data: []byte("audit(1790851328.281:50361):")}, now)
			if err != nil || (len(events) == 1) != test.retained {
				t.Fatalf("events=%#v err=%v", events, err)
			}
			if test.retained && (events[0].Category != CategorySELinuxAdministrative || len(events[0].Records) != 3 || string(events[0].Records[0].Raw) != string(message.Data)) {
				t.Fatalf("raw correlated evidence not retained: %#v", events)
			}
		})
	}
	if SuccessfulStateTransitionRecord(nil) {
		t.Fatal("nil record is a transition")
	}
}

func BenchmarkSuccessfulBooleanTransition(b *testing.B) {
	message := &libaudit.RawAuditMessage{Type: auparse.AUDIT_MAC_CONFIG_CHANGE, Data: []byte("audit(1790851328.281:50361): bool=httpd_can_network_connect val=0 old_val=1 auid=0 ses=535")}
	b.ReportAllocs()
	for b.Loop() {
		if !SuccessfulStateTransitionRecord(message) {
			b.Fatal("successful change not recognized")
		}
	}
}

func TestMACStatusRecognizesOnlySuccessfulRuntimeEnforcement(t *testing.T) {
	for _, test := range []struct {
		name, fields string
		boundary     bool
	}{
		{"forward", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1", true},
		{"reverse", "enforcing=1 old_enforcing=0 enabled=1 old-enabled=1 lsm=selinux res=1", true},
		{"failure", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=0", false},
		{"missing result", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux", false},
		{"unknown result", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=unknown", false},
		{"noop", "enforcing=1 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1", false},
		{"enablement", "enforcing=1 old_enforcing=0 enabled=1 old-enabled=0 lsm=selinux res=1", false},
		{"disablement", "enforcing=0 old_enforcing=0 enabled=0 old-enabled=1 lsm=selinux res=1", false},
		{"duplicate", "enforcing=0 enforcing=1 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1", false},
		{"duplicate result", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=0 res=1", false},
		{"invalid state", "enforcing=2 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1", false},
		{"unvalidated alias", "enforcing=0 old_enforcing=1 enabled=1 old_enabled=1 lsm=selinux res=1", false},
		{"contradictory result", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1 success=no", false},
		{"other LSM", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=other res=1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := &libaudit.RawAuditMessage{Type: auparse.AUDIT_MAC_STATUS, Data: []byte("audit(1790935524.757:51501): " + test.fields)}
			if SuccessfulStateTransitionRecord(message) != test.boundary {
				t.Fatalf("wrong boundary for %s", test.fields)
			}
			a := NewAssembler(DefaultConfig())
			now := time.Unix(1790935524, 757000000)
			a.Push(message, now)
			a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_SYSCALL, Data: []byte("audit(1790935524.757:51501): success=yes comm=\"setenforce\"")}, now)
			events, err := a.Push(&libaudit.RawAuditMessage{Type: auparse.AUDIT_EOE, Data: []byte("audit(1790935524.757:51501):")}, now)
			if err != nil || len(events) != 1 || events[0].Category != CategorySELinuxAdministrative || len(events[0].Records) != 3 {
				t.Fatalf("history/evidence not retained: %#v %v", events, err)
			}
		})
	}
}

func BenchmarkSuccessfulEnforcementTransition(b *testing.B) {
	message := &libaudit.RawAuditMessage{Type: auparse.AUDIT_MAC_STATUS, Data: []byte("audit(1790935524.757:51501): enforcing=0 old_enforcing=1 auid=0 ses=570 enabled=1 old-enabled=1 lsm=selinux res=1")}
	b.ReportAllocs()
	for b.Loop() {
		if !SuccessfulEnforcementChangeRecord(message) {
			b.Fatal("successful mode change not recognized")
		}
	}
}

func TestAssemblerCapacityEvictsOldest(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{Timeout: time.Hour, MaxInFlight: 1})
	first := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:1): avc: denied")}
	second := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:2): avc: denied")}
	a.Push(first, now)
	events, err := a.Push(second, now.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID.Sequence != 1 || events[0].Completion != CompletionCapacity {
		t.Fatalf("got %#v", events)
	}
}

func TestAssemblerBoundsCompletedTombstones(t *testing.T) {
	a := NewAssembler(Config{Timeout: time.Hour, MaxInFlight: 32, LateRecordTTL: time.Hour})
	now := time.Unix(100, 0)
	for sequence := range 5000 {
		avc := &libaudit.RawAuditMessage{Type: auparse.AUDIT_AVC, Data: []byte("audit(100.000:" + strconv.Itoa(sequence) + "): avc: denied")}
		eoe := &libaudit.RawAuditMessage{Type: auparse.AUDIT_EOE, Data: []byte("audit(100.000:" + strconv.Itoa(sequence) + "):")}
		if _, err := a.Push(avc, now); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Push(eoe, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.completed) > 32 {
		t.Fatalf("completed tombstones grew to %d", len(a.completed))
	}
}

func TestAssemblerReconstructsSanitizedRealHTTPDAVC(t *testing.T) {
	data, err := os.ReadFile("testdata/real-httpd-avc.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			TypeName string `json:"type_name"`
			Payload  string `json:"payload"`
		} `json:"records"`
		Expected struct {
			Sequence         uint32 `json:"sequence"`
			RecordCount      int    `json:"record_count"`
			CompletionReason string `json:"completion_reason"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	types := map[string]auparse.AuditMessageType{"AVC": auparse.AUDIT_AVC, "SYSCALL": auparse.AUDIT_SYSCALL, "PROCTITLE": auparse.AUDIT_PROCTITLE}
	a := NewAssembler(DefaultConfig())
	for _, record := range fixture.Records {
		if _, err := a.Push(&libaudit.RawAuditMessage{Type: types[record.TypeName], Data: []byte(record.Payload)}, time.Unix(1789425026, 418000000)); err != nil {
			t.Fatal(err)
		}
	}
	events := a.Close()
	if len(events) != 1 || events[0].ID.Sequence != fixture.Expected.Sequence || len(events[0].Records) != fixture.Expected.RecordCount || string(events[0].Completion) != fixture.Expected.CompletionReason {
		t.Fatalf("got %#v", events)
	}
	if !bytes.Contains(events[0].Records[0].Raw, []byte("httpd_t")) || !bytes.Contains(events[0].Records[1].Raw, []byte("/usr/sbin/httpd")) {
		t.Fatal("real AVC fixture evidence was not preserved")
	}
}

func TestAssemblerRealFleetEvidence(t *testing.T) {
	data, err := os.ReadFile("testdata/real-fleet.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name    string `json:"name"`
			Records []struct {
				TypeName string `json:"type_name"`
				Payload  string `json:"payload"`
			} `json:"records"`
			Expected struct {
				Sequence         uint32 `json:"sequence"`
				RecordCount      int    `json:"record_count"`
				CompletionReason string `json:"completion_reason"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	types := map[string]auparse.AuditMessageType{"AVC": auparse.AUDIT_AVC, "SYSCALL": auparse.AUDIT_SYSCALL, "PROCTITLE": auparse.AUDIT_PROCTITLE, "EOE": auparse.AUDIT_EOE}
	for _, capture := range fixture.Cases {
		t.Run(capture.Name, func(t *testing.T) {
			a := NewAssembler(DefaultConfig())
			now := time.Unix(1700000000, 0)
			var events []Event
			for _, record := range capture.Records {
				typeCode, ok := types[record.TypeName]
				if !ok {
					t.Fatalf("unsupported fixture record: %s", record.TypeName)
				}
				completed, err := a.Push(&libaudit.RawAuditMessage{Type: typeCode, Data: []byte(record.Payload)}, now)
				if err != nil {
					t.Fatal(err)
				}
				events = append(events, completed...)
			}
			events = append(events, a.Maintain(now.Add(time.Hour))...)
			if len(events) != 1 {
				t.Fatalf("got %d events", len(events))
			}
			event := events[0]
			if event.ID.Sequence != capture.Expected.Sequence || len(event.Records) != capture.Expected.RecordCount || string(event.Completion) != capture.Expected.CompletionReason {
				t.Fatalf("unexpected assembled event: %#v", event)
			}
			for i, record := range capture.Records {
				if string(event.Records[i].Raw) != record.Payload {
					t.Fatalf("raw record %d changed", i)
				}
			}
		})
	}
}
