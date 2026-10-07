// Package tracecontext validates and formats the supported W3C trace context version.
package tracecontext

import "encoding/hex"

// Traceparent is the version 00 W3C traceparent value without its wire separators.
type Traceparent struct {
	TraceID string
	SpanID  string
	Flags   uint8
}

// Parse accepts only a lowercase, nonzero version 00 traceparent value.
func Parse(value string) (Traceparent, bool) {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[:2] != "00" {
		return Traceparent{}, false
	}
	for _, char := range value {
		if char == '-' {
			continue
		}
		if !isLowerHex(char) {
			return Traceparent{}, false
		}
	}
	traceID, spanID := value[3:35], value[36:52]
	if allZero(traceID) || allZero(spanID) {
		return Traceparent{}, false
	}
	flags, err := hex.DecodeString(value[53:55])
	if err != nil || len(flags) != 1 {
		return Traceparent{}, false
	}
	return Traceparent{TraceID: traceID, SpanID: spanID, Flags: flags[0]}, true
}

// Format returns a canonical version 00 traceparent for the given trace/span IDs.
func Format(traceID, spanID string, flags uint8) (string, bool) {
	if len(traceID) != 32 || len(spanID) != 16 || allZero(traceID) || allZero(spanID) {
		return "", false
	}
	for _, char := range traceID + spanID {
		if !isLowerHex(char) {
			return "", false
		}
	}
	encodedFlags := hex.EncodeToString([]byte{flags})
	return "00-" + traceID + "-" + spanID + "-" + encodedFlags, true
}

func isLowerHex(char rune) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f'
}

func allZero(value string) bool {
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}
