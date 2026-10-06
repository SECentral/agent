package audit

import (
	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"strings"
	"testing"
	"time"
)

func portMessage(fields string) *libaudit.RawAuditMessage {
	return &libaudit.RawAuditMessage{Type: auparse.AUDIT_USER_MAC_CONFIG_CHANGE, Data: []byte("audit(1791285274.360:130): pid=1165 uid=0 auid=0 ses=3 msg='" + fields + ` comm="semanage" exe="/usr/bin/python3.9" res=success'`)}
}

func TestPortWritesAndNarrowHistory(t *testing.T) {
	add := "resrc=port op=add lport=23451 proto=6 tcontext=system_u:object_r:http_port_t:s0"
	for _, fields := range []string{add, strings.Replace(add, "op=add", "op=modify", 1), "resrc=port op=delete lport=23452-23453 proto=17"} {
		message := portMessage(fields)
		if !SuccessfulPortChangeRecord(message) || !SuccessfulStateTransitionRecord(message) {
			t.Fatalf("unrecognized write: %s", fields)
		}
		assembler := NewAssembler(DefaultConfig())
		if _, err := assembler.Push(message, time.Now()); err != nil {
			t.Fatal(err)
		}
		events := assembler.Close()
		if len(events) != 1 || events[0].Category != CategorySELinuxAdministrative {
			t.Fatalf("not retained: %#v", events)
		}
	}
	for _, fields := range []string{
		strings.Replace(add, "proto=6", "proto=tcp", 1), strings.Replace(add, "23451", "65536", 1),
		strings.Replace(add, "23451", "23453-23451", 1), strings.Replace(add, "23451", "0", 1),
		strings.Replace(add, "op=add", "op=unknown", 1), add + " proto=17", add + " proto=", add + ` proto="broken`, add + " res=failed", add + " res=success",
		strings.Replace(add, "tcontext=system_u:object_r:http_port_t:s0", "tcontext=broken", 1),
	} {
		message := portMessage(fields)
		if SuccessfulPortChangeRecord(message) {
			t.Fatalf("unsafe boundary: %s", fields)
		}
		if !PortChangeRecord(message) {
			t.Fatalf("lost port history: %s", fields)
		}
	}
	failed := portMessage(add)
	failed.Data = []byte(strings.Replace(string(failed.Data), "res=success", "res=failed", 1))
	if SuccessfulPortChangeRecord(failed) || !PortChangeRecord(failed) {
		t.Fatal("failure semantics")
	}
	unrelated := portMessage(strings.Replace(add, "resrc=port", "resrc=fcontext", 1))
	if PortChangeRecord(unrelated) || SuccessfulPortChangeRecord(unrelated) {
		t.Fatal("expanded semanage scope")
	}
	// Command text cannot upgrade another family.
	unrelated.Data = []byte(`audit(1791285274.360:130): msg='resrc=fcontext op=add comm="resrc=port" res=success'`)
	if PortChangeRecord(unrelated) {
		t.Fatal("command upgraded history")
	}
}

func BenchmarkSuccessfulPortChangeRecord(b *testing.B) {
	message := portMessage("resrc=port op=add lport=23451 proto=6 tcontext=system_u:object_r:http_port_t:s0")
	b.ReportAllocs()
	for b.Loop() {
		SuccessfulPortChangeRecord(message)
	}
}
