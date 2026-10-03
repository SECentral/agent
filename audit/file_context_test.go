package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
)

func TestExpectedContextTargetsRequiresAbsoluteCorrelatedPathAndType(t *testing.T) {
	event := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { execute } for comm="runcon" name="helper" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0`,
		`type=PATH msg=audit(100.000:7): item=0 name="/var/www/html/helper" inode=10 dev=fc:00 mode=0100755`,
	)

	targets := ExpectedContextTargets(event)
	if len(targets) != 1 {
		t.Fatalf("targets = %#v", targets)
	}
	if got := targets[0]; got.Path != "/var/www/html/helper" || got.FileType != "file" || got.ObjectClass != "file" || got.TargetContext != "unconfined_u:object_r:user_home_t:s0" {
		t.Fatalf("target = %#v", got)
	}
}

func TestExpectedContextTargetsPrefersAVCPathField(t *testing.T) {
	event := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for path="/srv/file" name="file" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=1 name="/srv/parent" inode=9 dev=fc:00 mode=040755`,
	)

	targets := ExpectedContextTargets(event)
	if len(targets) != 1 || targets[0].Path != "/srv/file" {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestExpectedContextTargetsChecksModeWhenPATHAlsoIdentifiesAVCPath(t *testing.T) {
	event := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for path="/srv/file" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/file" inode=10 dev=fc:00 mode=040755`,
	)

	targets := ExpectedContextTargets(event)
	if len(targets) != 1 || targets[0].FileType != "" || targets[0].FileTypeUnavailable != "file_type_conflict" {
		t.Fatalf("mode conflict target = %#v", targets)
	}
}

func TestExpectedContextTargetsDoesNotPromoteAVCBasename(t *testing.T) {
	event := expectedContextEvent(`type=AVC msg=audit(100.000:7): avc: denied { read } for name="helper" tcontext=system_u:object_r:var_t:s0 tclass=file`)

	if targets := ExpectedContextTargets(event); len(targets) != 0 {
		t.Fatalf("basename produced targets: %#v", targets)
	}
}

func TestExpectedContextTargetsSelectsOnlyUniquelyCorrelatedPath(t *testing.T) {
	event := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for name="helper" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/app/helper" inode=10 dev=fc:00 mode=0100644`,
		`type=PATH msg=audit(100.000:7): item=1 name="/srv/other/config" inode=11 dev=fc:00 mode=0100644`,
	)
	if targets := ExpectedContextTargets(event); len(targets) != 1 || targets[0].Path != "/srv/app/helper" {
		t.Fatalf("targets = %#v", targets)
	}

	ambiguous := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for name="helper" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/a/helper" inode=10 dev=fc:00 mode=0100644`,
		`type=PATH msg=audit(100.000:7): item=1 name="/srv/b/helper" inode=11 dev=fc:00 mode=0100644`,
	)
	if targets := ExpectedContextTargets(ambiguous); len(targets) != 0 {
		t.Fatalf("ambiguous paths produced targets: %#v", targets)
	}
}

func TestExpectedContextTargetsRejectsModeConflictAndUnsupportedClass(t *testing.T) {
	modeConflict := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for name="helper" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/helper" inode=10 dev=fc:00 mode=040755`,
	)
	targets := ExpectedContextTargets(modeConflict)
	if len(targets) != 1 || targets[0].FileType != "" || targets[0].FileTypeUnavailable != "file_type_conflict" {
		t.Fatalf("mode conflict target = %#v", targets)
	}

	unsupported := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for name="helper" tcontext=system_u:object_r:var_t:s0 tclass=process`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/helper" inode=10 dev=fc:00 mode=0100644`,
	)
	targets = ExpectedContextTargets(unsupported)
	if len(targets) != 1 || targets[0].FileType != "" || targets[0].FileTypeUnavailable != "unsupported_object_class" {
		t.Fatalf("unsupported class target = %#v", targets)
	}
}

func TestExpectedContextTargetsSkipsMultipleAVCs(t *testing.T) {
	event := expectedContextEvent(
		`type=AVC msg=audit(100.000:7): avc: denied { read } for name="one" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=AVC msg=audit(100.000:7): avc: denied { write } for name="two" tcontext=system_u:object_r:var_t:s0 tclass=file`,
		`type=PATH msg=audit(100.000:7): item=0 name="/srv/one" inode=10 dev=fc:00 mode=0100644`,
		`type=PATH msg=audit(100.000:7): item=1 name="/srv/two" inode=11 dev=fc:00 mode=0100644`,
	)
	targets := ExpectedContextTargets(event)
	if len(targets) != 0 {
		t.Fatalf("multi-AVC event produced targets: %#v", targets)
	}
}

func TestResolveExpectedContextUsesMatchpathconAndTimesResult(t *testing.T) {
	resolver := writeResolver(t, "printf 'system_u:object_r:expected_t:s0\\n'\n")
	t.Setenv("PATH", filepath.Dir(resolver)+string(os.PathListSeparator)+os.Getenv("PATH"))

	result := ResolveExpectedContext(t.Context(), ExpectedContextTarget{Path: "/srv/file", FileType: "file"})
	if result.Status != "resolved" || result.Context != "system_u:object_r:expected_t:s0" || result.At.IsZero() {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolveExpectedContextReportsUnavailableAndTimeout(t *testing.T) {
	missing := t.TempDir()
	t.Setenv("PATH", missing)
	result := ResolveExpectedContext(t.Context(), ExpectedContextTarget{Path: "/srv/file", FileType: "file"})
	if result.Status != "unavailable" || result.Reason != "resolver_unavailable" {
		t.Fatalf("missing resolver result = %#v", result)
	}

	resolver := writeResolver(t, "printf '<<none>>\\n'\n")
	t.Setenv("PATH", filepath.Dir(resolver)+string(os.PathListSeparator)+os.Getenv("PATH"))
	result = ResolveExpectedContext(t.Context(), ExpectedContextTarget{Path: "/srv/file", FileType: "file"})
	if result.Status != "unavailable" || result.Reason != "no_expected_context" {
		t.Fatalf("empty file-context mapping result = %#v", result)
	}

	resolver = writeResolver(t, "exec /bin/sleep 5\n")
	t.Setenv("PATH", filepath.Dir(resolver)+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	result = ResolveExpectedContext(ctx, ExpectedContextTarget{Path: "/srv/file", FileType: "file"})
	if result.Status != "error" || result.Reason != "resolver_timeout" {
		t.Fatalf("timeout result = %#v", result)
	}
}

func expectedContextEvent(records ...string) Event {
	timestamp := time.Unix(100, 0).UTC()
	event := Event{Category: CategoryAVC, ID: AuditEventID{Timestamp: timestamp, Sequence: 7}}
	for position, raw := range records {
		typ := auparse.AUDIT_AVC
		typeName := "AVC"
		if strings.HasPrefix(raw, "type=PATH") {
			typ = auparse.AUDIT_PATH
			typeName = "PATH"
		}
		event.Records = append(event.Records, Record{Position: position, Type: typ, TypeName: typeName, Timestamp: timestamp, Sequence: 7, Raw: []byte(raw)})
	}
	return event
}

func writeResolver(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "matchpathcon")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
