// Package logging creates structured JSON logs and redacts sensitive attributes.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

const (
	redacted = "[REDACTED]"
	omitted  = "[OMITTED]"
)

var safeAttributeNames = map[string]struct{}{
	"time": {}, "level": {}, "msg": {}, "requestid": {}, "traceid": {},
	"role": {}, "environment": {}, "listenaddress": {}, "component": {},
	"errorcode": {}, "errortype": {}, "durationms": {}, "httpstatus": {},
	"operation": {}, "result": {}, "attempt": {}, "policyversion": {},
	"count": {}, "retryafterms": {},
}

var sensitiveNames = map[string]struct{}{
	"authorization": {}, "proxyauthorization": {}, "cookie": {}, "setcookie": {},
	"password": {}, "passwd": {}, "secret": {}, "clientsecret": {}, "credential": {}, "credentials": {}, "auth": {},
	"accesstoken": {}, "refreshtoken": {}, "token": {}, "apikey": {},
	"privatekey": {}, "prompt": {}, "prompttext": {}, "document": {},
	"documenttext": {}, "body": {}, "rawbody": {}, "sql": {}, "query": {}, "querytext": {},
	"url": {}, "uri": {}, "dsn": {}, "connectionstring": {}, "email": {},
}

// NewJSON returns a JSON logger with field-level redaction. Log messages themselves
// must be static and must never contain secrets or untrusted customer text.
func NewJSON(output io.Writer, level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttribute,
	})
	return slog.New(handler)
}

func redactAttribute(groups []string, attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if containsSensitiveName(attr.Key) || sensitiveGroup(groups) {
		return slog.String(attr.Key, redacted)
	}
	if !isSafeAttribute(attr.Key) {
		return slog.String(attr.Key, omitted)
	}
	if attr.Value.Kind() != slog.KindGroup {
		return attr
	}

	childGroups := append(append([]string(nil), groups...), attr.Key)
	children := attr.Value.Group()
	for i := range children {
		children[i] = redactAttribute(childGroups, children[i])
	}
	return slog.Attr{Key: attr.Key, Value: slog.GroupValue(children...)}
}

func sensitiveGroup(groups []string) bool {
	for _, group := range groups {
		if containsSensitiveName(group) {
			return true
		}
	}
	return false
}

func containsSensitiveName(key string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(key) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			normalized.WriteRune(r)
		}
	}
	_, found := sensitiveNames[normalized.String()]
	return found
}

func isSafeAttribute(key string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(key) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			normalized.WriteRune(r)
		}
	}
	_, found := safeAttributeNames[normalized.String()]
	return found
}
