package tracecontext

import "testing"

const testTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseAndFormatTraceparent(t *testing.T) {
	parsed, ok := Parse(testTraceparent)
	if !ok || parsed.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || parsed.SpanID != "00f067aa0ba902b7" || parsed.Flags != 1 {
		t.Fatalf("parsed traceparent=%+v valid=%v", parsed, ok)
	}
	formatted, ok := Format(parsed.TraceID, parsed.SpanID, parsed.Flags)
	if !ok || formatted != testTraceparent {
		t.Fatalf("formatted traceparent=%q valid=%v", formatted, ok)
	}
}

func TestParseRejectsUnsupportedOrMalformedTraceparent(t *testing.T) {
	for _, invalid := range []string{
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
		" 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
	} {
		if _, ok := Parse(invalid); ok {
			t.Fatalf("invalid traceparent accepted: %q", invalid)
		}
	}
}

func TestFormatRejectsInvalidIdentifiers(t *testing.T) {
	for _, pair := range [][2]string{
		{"00000000000000000000000000000000", "00f067aa0ba902b7"},
		{"4bf92f3577b34da6a3ce929d0e0e4736", "0000000000000000"},
		{"4BF92F3577B34DA6A3CE929D0E0E4736", "00f067aa0ba902b7"},
	} {
		if _, ok := Format(pair[0], pair[1], 1); ok {
			t.Fatalf("invalid trace/span identifiers accepted: %q / %q", pair[0], pair[1])
		}
	}
}
