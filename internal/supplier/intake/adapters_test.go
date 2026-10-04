package intake

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClamDStreamsBoundedProtocolAndClassifiesVerdicts(t *testing.T) {
	data := bytes.Repeat([]byte("evidence"), 20_000)
	for name, reply := range map[string]string{"clean": "stream: OK\x00", "infected": "stream: Eicar-Test-Signature FOUND\x00"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				reader := bufio.NewReader(conn)
				command, err := reader.ReadString(0)
				if err != nil || command != "zINSTREAM\x00" {
					serverErr <- fmt.Errorf("command=%q err=%v", command, err)
					return
				}
				var received bytes.Buffer
				for {
					var size [4]byte
					if _, err := io.ReadFull(reader, size[:]); err != nil {
						serverErr <- err
						return
					}
					length := binary.BigEndian.Uint32(size[:])
					if length == 0 {
						break
					}
					if _, err := io.CopyN(&received, reader, int64(length)); err != nil {
						serverErr <- err
						return
					}
				}
				if !bytes.Equal(received.Bytes(), data) {
					serverErr <- fmt.Errorf("scanner received %d bytes, want %d", received.Len(), len(data))
					return
				}
				_, err = io.WriteString(conn, reply)
				serverErr <- err
			}()
			client := &ClamD{address: listener.Addr().String(), timeout: time.Second, dialer: &net.Dialer{Timeout: time.Second}}
			err = client.Scan(context.Background(), bytes.NewReader(data))
			if name == "clean" && err != nil {
				t.Fatalf("clean verdict error=%v", err)
			}
			if name == "infected" && err != ErrMalwareFound {
				t.Fatalf("infected verdict error=%v", err)
			}
			if serverErr := <-serverErr; serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestClamDConfigurationAndIndeterminateResponseFailClosed(t *testing.T) {
	for _, address := range []string{"example.com:3310", "clamav:1234", "localhost:3310/path", "127.0.0.1:0"} {
		if _, err := NewClamD(address, time.Second); err == nil {
			t.Errorf("accepted scanner endpoint %q", address)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString(0)
		for {
			var size [4]byte
			if _, err := io.ReadFull(reader, size[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 {
				break
			}
			_, _ = io.CopyN(io.Discard, reader, int64(n))
		}
		_, _ = io.WriteString(conn, "unknown\x00")
	}()
	client := &ClamD{address: listener.Addr().String(), timeout: time.Second, dialer: &net.Dialer{Timeout: time.Second}}
	if err := client.Scan(context.Background(), strings.NewReader("safe")); err == nil || strings.Contains(err.Error(), "unknown") {
		t.Fatalf("indeterminate verdict was not failed closed/redacted: %v", err)
	}
}

func TestTikaExtractorBoundsAndRedactsSandboxResponses(t *testing.T) {
	data := []byte("%PDF-1.7\nsynthetic input")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/tika" || r.Header.Get("Accept") != "text/plain" || r.Header.Get("Content-Type") != string(FormatPDF) {
			t.Errorf("unexpected sandbox request method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("sandbox input=%q err=%v", got, err)
		}
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		_, _ = io.WriteString(w, "extracted text")
	}))
	defer server.Close()
	extractor := &TikaExtractor{endpoint: server.URL, client: &http.Client{Timeout: time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	result, err := extractor.Extract(context.Background(), FormatPDF, bytes.NewReader(data), MaxExtractedSize)
	if err != nil || string(result) != "extracted text" {
		t.Fatalf("extracted=%q err=%v", result, err)
	}
	for name, handler := range map[string]http.HandlerFunc{
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, strings.Repeat("x", int(MaxExtractedSize+1)))
		},
		"wrong type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"secret":"supplier content"}`)
		},
		"parser error": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "parser said supplier secret", http.StatusInternalServerError)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client := &TikaExtractor{endpoint: server.URL, client: &http.Client{Timeout: time.Second}}
			_, err := client.Extract(context.Background(), FormatPDF, bytes.NewReader(data), MaxExtractedSize)
			if err == nil || strings.Contains(err.Error(), "supplier") {
				t.Fatalf("sandbox failure did not fail closed/redact: %v", err)
			}
		})
	}
}

func TestTikaExtractorConfigurationRejectsRedirectTargetsAndUnqualifiedHosts(t *testing.T) {
	for _, endpoint := range []string{"https://tika:9998", "http://example.com:9998", "http://user@tika:9998", "http://tika:9998/path", "http://tika:9998?url=http://169.254.169.254/"} {
		if _, err := NewTikaExtractor(endpoint, time.Second); err == nil {
			t.Errorf("accepted extractor endpoint %q", endpoint)
		}
	}
	if _, err := NewTikaExtractor(defaultTikaURL, defaultTikaLimit); err != nil {
		t.Fatalf("fixed local sandbox endpoint rejected: %v", err)
	}
}

func TestTikaExtractorNeverInheritsHostProxyConfiguration(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example.test:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:8080")
	extractor, err := NewTikaExtractor(defaultTikaURL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := extractor.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("Tika transport must connect directly to its fixed internal endpoint")
	}
}
