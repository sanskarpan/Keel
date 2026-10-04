package intake

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultClamDPort = "3310"
	defaultTikaURL   = "http://tika:9998"
	defaultTikaLimit = 45 * time.Second
)

// ClamD speaks the bounded INSTREAM protocol. Its endpoint can only be the local test daemon
// or the fixed service name in Keel's isolated Compose network.
type ClamD struct {
	address string
	timeout time.Duration
	dialer  *net.Dialer
}

func NewClamD(address string, timeout time.Duration) (*ClamD, error) {
	if timeout < time.Second || timeout > 2*time.Minute {
		return nil, errors.New("scanner timeout must be between 1s and 2m")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != defaultClamDPort || !(host == "clamav" || host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil, errors.New("scanner endpoint must be clamav:3310 or loopback:3310")
	}
	return &ClamD{address: net.JoinHostPort(host, port), timeout: timeout, dialer: &net.Dialer{Timeout: timeout}}, nil
}

func (c *ClamD) Scan(ctx context.Context, source io.Reader) error {
	if c == nil || ctx == nil || source == nil {
		return errors.New("scanner context and content are required")
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := c.dialer.DialContext(dialCtx, "tcp", c.address)
	if err != nil {
		return errors.New("malware scanner could not be reached")
	}
	defer conn.Close()
	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return errors.New("malware scanner deadline could not be set")
	}
	if err := writeAll(conn, []byte("zINSTREAM\x00")); err != nil {
		return errors.New("malware scanner rejected the stream command")
	}
	buffer := make([]byte, 64<<10)
	noProgress := 0
	var scanned int64
	for {
		if err := ctx.Err(); err != nil {
			return errors.New("malware scan canceled")
		}
		n, readErr := source.Read(buffer)
		if n == 0 && readErr == nil {
			noProgress++
			if noProgress >= 100 {
				return errors.New("upload stream made no progress")
			}
			continue
		}
		noProgress = 0
		if n > 0 {
			scanned += int64(n)
			if scanned > MaxUploadBytes {
				return errors.New("upload exceeds malware scanner size limit")
			}
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(n))
			if err := writeAll(conn, size[:]); err != nil {
				return errors.New("malware scanner rejected a stream frame")
			}
			if err := writeAll(conn, buffer[:n]); err != nil {
				return errors.New("malware scanner rejected stream content")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errors.New("upload stream could not be scanned")
		}
	}
	var zero [4]byte
	if err := writeAll(conn, zero[:]); err != nil {
		return errors.New("malware scanner did not accept the completed stream")
	}
	line, err := bufio.NewReaderSize(conn, 4096).ReadSlice('\x00')
	if err != nil || len(line) > 4096 {
		return errors.New("malware scanner returned an invalid response")
	}
	lineText := strings.TrimSpace(strings.TrimSuffix(string(line), "\x00"))
	if strings.HasSuffix(lineText, " FOUND") {
		return ErrMalwareFound
	}
	if !strings.HasSuffix(lineText, " OK") {
		return errors.New("malware scanner returned an indeterminate verdict")
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// TikaExtractor sends documents only to the fixed internal sandbox endpoint. Redirects are
// disabled, source files and extracted text are both bounded, and errors do not include parser
// response bodies that could contain supplier-controlled content.
type TikaExtractor struct {
	endpoint string
	client   *http.Client
}

func NewTikaExtractor(endpoint string, timeout time.Duration) (*TikaExtractor, error) {
	if timeout < time.Second || timeout > 2*time.Minute {
		return nil, errors.New("extractor timeout must be between 1s and 2m")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !(endpoint == defaultTikaURL || endpoint == "http://127.0.0.1:9998" || endpoint == "http://localhost:9998") {
		return nil, errors.New("extractor endpoint must be the fixed tika service or loopback endpoint")
	}
	return &TikaExtractor{
		endpoint: strings.TrimRight(endpoint, "/"),
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// Never inherit HTTP_PROXY/HTTPS_PROXY. The document body must stay on
				// the fixed internal scanner network even when the host has a proxy.
				Proxy:                 nil,
				DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
				MaxIdleConnsPerHost:   2,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("extractor redirects are disabled")
			},
		},
	}, nil
}

func (e *TikaExtractor) Extract(ctx context.Context, format Format, source io.Reader, outputLimit int64) ([]byte, error) {
	if e == nil || ctx == nil || source == nil || outputLimit < 1 || outputLimit > MaxExtractedSize {
		return nil, errors.New("extractor arguments are invalid")
	}
	if format != FormatPDF && format != FormatDOCX && format != FormatText {
		return nil, fmt.Errorf("unsupported extraction format %q", format)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, e.endpoint+"/tika", source)
	if err != nil {
		return nil, errors.New("extractor request could not be created")
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", string(format))
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, errors.New("sandboxed extractor is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/plain") {
		return nil, errors.New("sandboxed extractor rejected the document")
	}
	text, err := io.ReadAll(io.LimitReader(resp.Body, outputLimit+1))
	if err != nil || int64(len(text)) > outputLimit || !utf8ValidText(text) {
		return nil, errors.New("sandboxed extractor exceeded or violated the output contract")
	}
	return text, nil
}

func utf8ValidText(data []byte) bool {
	return utf8.Valid(data) && bytes.IndexByte(data, 0) < 0
}
