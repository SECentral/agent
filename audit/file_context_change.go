package audit

import (
	"bytes"
	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var mappingWriteContext = regexp.MustCompile(`^system_u:object_r:[A-Za-z_][A-Za-z0-9_]*:(?:s0)?$`)

func FileContextChangeFields(message *libaudit.RawAuditMessage) map[string]string {
	if message == nil || !bytes.Contains(message.Data, []byte("resrc=fcontext")) {
		return nil
	}
	fields := userChangeFields(message)
	if fields == nil || fields["resrc"] != "fcontext" ||
		(fields["op"] != "add" && fields["op"] != "modify" && fields["op"] != "delete") ||
		(fields["ftype"] != "any" && fields["ftype"] != "file") {
		return nil
	}
	expression := fields["tglob"]
	if len(expression) < 3 || len(expression) > 4098 || expression[0] != '"' || expression[len(expression)-1] != '"' {
		return nil
	}
	expression = expression[1 : len(expression)-1]
	if !utf8.ValidString(expression) || !strings.HasPrefix(expression, "/") || strings.ContainsAny(expression, `"\`) || strings.ContainsFunc(expression, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil
	}
	for _, key := range []string{"success", "old_tcontext", "old_type", "sglob", "lport", "proto"} {
		if _, present := fields[key]; present {
			return nil
		}
	}
	if fields["op"] == "delete" {
		if _, present := fields["tcontext"]; present {
			return nil
		}
	} else if !mappingWriteContext.MatchString(fields["tcontext"]) {
		return nil
	}
	return fields
}

func SuccessfulFileContextChangeRecord(message *libaudit.RawAuditMessage) bool {
	fields := FileContextChangeFields(message)
	return fields != nil && fields["res"] == "success"
}

func FileContextChangeRecord(message *libaudit.RawAuditMessage) bool {
	if message == nil || message.Type != auparse.AUDIT_USER_MAC_CONFIG_CHANGE {
		return false
	}
	for _, match := range userChangeMessage.FindAllStringSubmatch(string(message.Data), -1) {
		if match[1] == "resrc=fcontext" || strings.HasPrefix(match[1], "resrc=fcontext ") {
			return true
		}
	}
	return false
}
