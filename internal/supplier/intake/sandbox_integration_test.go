package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPinnedSandboxServicesScanAndExtract(t *testing.T) {
	address, endpoint := os.Getenv("KEEL_TEST_CLAMD_ADDRESS"), os.Getenv("KEEL_TEST_TIKA_ENDPOINT")
	if address == "" && endpoint == "" {
		t.Skip("set KEEL_TEST_CLAMD_ADDRESS and KEEL_TEST_TIKA_ENDPOINT for pinned sandbox integration")
	}
	if address == "" || endpoint == "" {
		t.Fatal("both pinned sandbox endpoints must be configured together")
	}
	scanner, err := NewClamD(address, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTikaExtractor(endpoint, 45*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clean := []byte("Keel supplier sandbox integration text.\n")
	digest := sha256.Sum256(clean)
	metadata := UploadMetadata{Filename: "evidence.txt", ContentType: string(FormatText), Size: int64(len(clean)), SHA256: hex.EncodeToString(digest[:])}
	// Wait for each daemon's readiness without treating a slow Java/definition startup as a pass.
	ready := time.NewTicker(500 * time.Millisecond)
	defer ready.Stop()
	for {
		if err := pingClamD(ctx, address); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("pinned ClamAV did not become ready")
		case <-ready.C:
		}
	}
	if err := scanner.Scan(ctx, bytes.NewReader(clean)); err != nil {
		t.Fatalf("pinned ClamAV clean-file scan failed: %v", err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/version", nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("pinned Tika did not become ready: %v", err)
		case <-ready.C:
		}
	}
	processed, err := Process(ctx, metadata, bytes.NewReader(clean), scanner, extractor)
	if err != nil {
		t.Fatalf("real ClamAV + Tika processing failed: %v", err)
	}
	if !strings.Contains(string(processed.Text), "supplier sandbox integration text") {
		t.Fatalf("Tika output omitted fixture text: %q", processed.Text)
	}
	const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	if err := scanner.Scan(ctx, strings.NewReader(eicar)); !errors.Is(err, ErrMalwareFound) {
		t.Fatalf("ClamAV did not reject the standard EICAR fixture: %v", err)
	}
}

func pingClamD(ctx context.Context, address string) error {
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("zPING\x00")); err != nil {
		return err
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if string(response) != "PONG\x00" {
		return errors.New("ClamAV readiness response was invalid")
	}
	return nil
}
