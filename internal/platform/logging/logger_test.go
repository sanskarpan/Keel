package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewJSONRedactsSensitiveAttributesAndGroups(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSON(&output, slog.LevelInfo)
	logger.Info("request completed",
		slog.String("request_id", "req-safe"),
		slog.String("Authorization", "Bearer top-secret-token"),
		slog.Group("credentials",
			slog.String("username", "private-user"),
			slog.String("password", "private-password"),
		),
		slog.Group("request", slog.String("prompt_text", "private prompt")),
	)

	line := output.String()
	for _, secret := range []string{"top-secret-token", "private-user", "private-password", "private prompt"} {
		if strings.Contains(line, secret) {
			t.Fatalf("log contains sensitive value %q: %s", secret, line)
		}
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not valid JSON: %v", err)
	}
	if record["request_id"] != "req-safe" {
		t.Fatalf("safe field was lost: %#v", record)
	}
	if record["Authorization"] != redacted {
		t.Fatalf("authorization not redacted: %#v", record["Authorization"])
	}
	credentials, ok := record["credentials"].(map[string]any)
	if !ok || credentials["username"] != redacted || credentials["password"] != redacted {
		t.Fatalf("sensitive group not redacted: %#v", record["credentials"])
	}
	request, ok := record["request"].(map[string]any)
	if !ok || request["prompt_text"] != redacted {
		t.Fatalf("nested prompt not redacted: %#v", record["request"])
	}
}

func TestNewJSONHonorsMinimumLevel(t *testing.T) {
	var output bytes.Buffer
	NewJSON(&output, slog.LevelWarn).Info("suppressed")
	if output.Len() != 0 {
		t.Fatalf("below-threshold log was emitted: %s", output.String())
	}
}
