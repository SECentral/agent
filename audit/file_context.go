package audit

import (
	"context"
	"errors"
	"maps"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"golang.org/x/sys/unix"
)

type ExpectedContextTarget struct {
	Path                string
	ObjectClass         string
	FileType            string
	FileTypeUnavailable string
	TargetContext       string
	SourceContext       string
	Permissions         []string
}

type ExpectedContextResult struct {
	Context string
	Status  string
	Reason  string
	At      time.Time
}

var (
	auditFieldPattern = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_]*)=(?:"((?:\\.|[^"])*)"|([^\s]+))`)
	deniedPermissions = regexp.MustCompile(`\bdenied\s+\{([^}]*)\}`)
)

// ExpectedContextTargets only returns paths linked to one AVC by raw audit
// evidence. Basenames and inferred paths are never eligible.
func ExpectedContextTargets(event Event) []ExpectedContextTarget {
	if event.Category != CategoryAVC {
		return nil
	}
	paths := eventPaths(event.Records)
	var avcs []Record
	for _, record := range event.Records {
		if record.Type == auparse.AUDIT_AVC || record.Type == auparse.AUDIT_USER_AVC {
			avcs = append(avcs, record)
		}
	}
	// The server normalizes one denial tuple per raw event; do not inspect a
	// multi-AVC envelope whose PATH records cannot be bound to one tuple.
	if len(avcs) != 1 {
		return nil
	}
	var targets []ExpectedContextTarget
	for _, record := range avcs {
		fields := parseAuditFields(record.Raw)
		if fields["tcontext"] == "" || fields["tclass"] == "" {
			continue
		}
		path, _, mode, ok := pathForAVC(fields, record.Position, paths, event.Records)
		if !ok {
			continue
		}
		class := fields["tclass"]
		fileType, reason := matchPathconType(class, mode)
		permissions := deniedPermissions.FindSubmatch(record.Raw)
		var denied []string
		if len(permissions) == 2 {
			denied = strings.Fields(string(permissions[1]))
			slices.Sort(denied)
		}
		if len(denied) == 0 {
			continue
		}
		targets = append(targets, ExpectedContextTarget{
			Path:                path,
			ObjectClass:         class,
			FileType:            fileType,
			FileTypeUnavailable: reason,
			TargetContext:       fields["tcontext"],
			SourceContext:       fields["scontext"],
			Permissions:         denied,
		})
	}
	slices.SortFunc(targets, func(a, b ExpectedContextTarget) int {
		if order := strings.Compare(a.Path, b.Path); order != 0 {
			return order
		}
		if order := strings.Compare(a.ObjectClass, b.ObjectClass); order != 0 {
			return order
		}
		return strings.Compare(a.TargetContext, b.TargetContext)
	})
	unique := targets[:0]
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		key := strings.Join([]string{target.Path, target.ObjectClass, target.FileType, target.FileTypeUnavailable}, "\x00")
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, target)
	}
	return unique
}

func pathForAVC(fields map[string]string, avcPosition int, paths []pathRecord, records []Record) (string, int, string, bool) {
	var direct []string
	for _, record := range records {
		if record.Position != avcPosition {
			continue
		}
		for _, field := range auditFieldPattern.FindAllSubmatch(record.Raw, -1) {
			if string(field[1]) == "path" && len(field) > 3 {
				path := auditFieldValue(field)
				if filepath.IsAbs(path) {
					direct = append(direct, path)
				}
			}
		}
	}
	if len(direct) > 0 {
		direct = slices.Compact(slices.Sorted(slices.Values(direct)))
		if len(direct) != 1 {
			return "", -1, "", false
		}
		pathPosition, mode := avcPosition, fields["mode"]
		if index := slices.IndexFunc(paths, func(candidate pathRecord) bool { return candidate.path == direct[0] }); index >= 0 {
			pathPosition, mode = paths[index].position, paths[index].mode
		}
		return direct[0], pathPosition, mode, true
	}

	var candidates []pathRecord
	for _, candidate := range paths {
		if fields["name"] != "" && filepath.Base(candidate.path) != filepath.Base(fields["name"]) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) != 1 {
		return "", -1, "", false
	}
	// Without an AVC basename, a PATH name is attributable only when the
	// audit event has one AVC and one absolute path candidate.
	if fields["name"] == "" && len(paths) != 1 {
		return "", -1, "", false
	}
	return candidates[0].path, candidates[0].position, candidates[0].mode, true
}

type pathRecord struct {
	path     string
	mode     string
	position int
}

func eventPaths(records []Record) []pathRecord {
	paths := make(map[string]pathRecord)
	for _, record := range records {
		fields := parseAuditFields(record.Raw)
		if record.Type == auparse.AUDIT_PATH || record.TypeName == "PATH" {
			if name := fields["name"]; filepath.IsAbs(name) {
				paths[name] = pathRecord{path: name, mode: fields["mode"], position: record.Position}
			}
		}
		if path := fields["path"]; filepath.IsAbs(path) {
			if _, exists := paths[path]; !exists {
				paths[path] = pathRecord{path: path, mode: fields["mode"], position: record.Position}
			}
		}
	}
	result := slices.Collect(maps.Values(paths))
	slices.SortFunc(result, func(a, b pathRecord) int { return strings.Compare(a.path, b.path) })
	return result
}

func parseAuditFields(raw []byte) map[string]string {
	fields := make(map[string]string)
	for _, match := range auditFieldPattern.FindAllSubmatch(raw, -1) {
		fields[string(match[1])] = auditFieldValue(match)
	}
	return fields
}

func auditFieldValue(match [][]byte) string {
	if len(match) > 2 && match[2] != nil {
		value, err := strconv.Unquote(`"` + string(match[2]) + `"`)
		if err == nil {
			return value
		}
	}
	if len(match) > 3 {
		return string(match[3])
	}
	return ""
}

func matchPathconType(objectClass, mode string) (string, string) {
	classType := map[string]string{
		"file": "file", "dir": "dir", "fifo_file": "pipe", "chr_file": "chr_file",
		"blk_file": "blk_file", "lnk_file": "lnk_file", "sock_file": "sock_file",
	}[objectClass]
	if classType == "" {
		return "", "unsupported_object_class"
	}
	modeType := fileTypeFromMode(mode)
	if classType != "" && modeType != "" && classType != modeType {
		return "", "file_type_conflict"
	}
	return classType, ""
}

func fileTypeFromMode(value string) string {
	if value == "" {
		return ""
	}
	mode, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return ""
	}
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFIFO:
		return "pipe"
	case unix.S_IFCHR:
		return "chr_file"
	case unix.S_IFBLK:
		return "blk_file"
	case unix.S_IFLNK:
		return "lnk_file"
	case unix.S_IFSOCK:
		return "sock_file"
	default:
		return ""
	}
}

func ResolveExpectedContext(ctx context.Context, target ExpectedContextTarget) ExpectedContextResult {
	result := ExpectedContextResult{Status: "error", Reason: "resolver_failed"}
	if target.FileType == "" {
		result.Status = "unavailable"
		result.Reason = target.FileTypeUnavailable
		result.At = time.Now().UTC()
		return result
	}
	output, err := exec.CommandContext(ctx, "matchpathcon", "-n", "-m", target.FileType, target.Path).Output()
	if err != nil {
		result.At = time.Now().UTC()
		if errors.Is(err, exec.ErrNotFound) {
			result.Status = "unavailable"
			result.Reason = "resolver_unavailable"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.Reason = "resolver_timeout"
		}
		return result
	}
	value := strings.TrimSpace(string(output))
	result.At = time.Now().UTC()
	if strings.EqualFold(value, "<<none>>") {
		result.Status = "unavailable"
		result.Reason = "no_expected_context"
		return result
	}
	if value == "" || strings.ContainsAny(value, "\r\n") || !validSELinuxContext(value) {
		result.Reason = "invalid_resolver_output"
		return result
	}
	result.Context = value
	result.Status = "resolved"
	result.Reason = ""
	return result
}

func validSELinuxContext(value string) bool {
	parts := strings.SplitN(value, ":", 4)
	return len(parts) >= 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}
