package audit

import (
	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"strings"
	"testing"
	"time"
)

func mappingMessage(fields string) *libaudit.RawAuditMessage {
	return &libaudit.RawAuditMessage{Type: auparse.AUDIT_USER_MAC_CONFIG_CHANGE, Data: []byte("audit(1791296443.045:756): pid=2606 uid=0 auid=0 ses=29 msg='" + fields + ` comm="semanage" exe="/usr/bin/python3.9" res=success'`)}
}
func TestFileContextWriteRecognitionAndHistory(t *testing.T) {
	add := `resrc=fcontext op=add tglob="/srv/secentral-fcontext(/.*)?" ftype=any tcontext=system_u:object_r:httpd_sys_content_t:`
	for _, fields := range []string{add, strings.Replace(add, "op=add", "op=modify", 1), `resrc=fcontext op=delete tglob="/srv/secentral-fcontext(/.*)?" ftype=any`, `resrc=fcontext op=add tglob="/srv/secentral-fcontext/file" ftype=file tcontext=system_u:object_r:user_home_t:s0`} {
		message := mappingMessage(fields)
		if !SuccessfulFileContextChangeRecord(message) || strings.Join(StateTransitionFields(message), ",") != "file_context_mappings" {
			t.Fatalf("missed %s", fields)
		}
		assembler := NewAssembler(DefaultConfig())
		if _, err := assembler.Push(message, time.Now()); err != nil {
			t.Fatal(err)
		}
		events := assembler.Close()
		if len(events) != 1 || events[0].Category != CategorySELinuxAdministrative {
			t.Fatal("mapping evidence discarded")
		}
	}
	for _, fields := range []string{add + " res=failed", add + " ftype=file", add + " tglob=", strings.Replace(add, "ftype=any", "ftype=unknown", 1), strings.Replace(add, "op=add", "op=modify-equal", 1), strings.Replace(add, `"/srv/secentral-fcontext(/.*)?"`, `"relative"`, 1), strings.Replace(add, `tglob="/srv/secentral-fcontext(/.*)?"`, "tglob=deadbeef", 1), strings.Replace(add, "tcontext=system_u:object_r:httpd_sys_content_t:", "tcontext=unknown", 1)} {
		message := mappingMessage(fields)
		if SuccessfulFileContextChangeRecord(message) || !FileContextChangeRecord(message) {
			t.Fatalf("bad boundary/history %s", fields)
		}
	}
	other := mappingMessage(`resrc=login op=add tglob="/srv/test" ftype=any tcontext=system_u:object_r:var_t:`)
	if SuccessfulFileContextChangeRecord(other) || FileContextChangeRecord(other) {
		t.Fatal("expanded unrelated family")
	}
}
func BenchmarkSuccessfulFileContextChangeRecord(b *testing.B) {
	message := mappingMessage(`resrc=fcontext op=add tglob="/srv/secentral-fcontext(/.*)?" ftype=any tcontext=system_u:object_r:httpd_sys_content_t:`)
	b.ReportAllocs()
	for b.Loop() {
		SuccessfulFileContextChangeRecord(message)
	}
}
