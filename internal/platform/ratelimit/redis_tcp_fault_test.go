package ratelimit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisLostReplyAfterScriptCommitOverTCP(t *testing.T) {
	redisURL := strings.TrimSpace(os.Getenv("KEEL_TEST_REDIS_URL"))
	if redisURL == "" {
		t.Skip("set KEEL_TEST_REDIS_URL for TCP-level Redis fault injection")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("parse Redis integration URL")
	}
	if options.TLSConfig != nil {
		t.Skip("TCP-level RESP fault proxy requires a plaintext disposable Redis fixture")
	}
	options.MaxRetries = -1
	directClient := redis.NewClient(options)
	t.Cleanup(func() { _ = directClient.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := directClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to disposable Redis service: %v", err)
	}
	limiterConfig := Config{Region: "us-east-1", HomeRegion: "us-east-1", KeyID: "tcp-fault-v1",
		Secret: []byte(strings.Repeat("t", 32)), ReplayTTL: time.Minute}
	directLimiter, err := New(directClient, limiterConfig)
	if err != nil {
		t.Fatal("create direct limiter")
	}
	policy := Policy{Digest: strings.Repeat("d", 64), CapacityUnits: 10, RefillUnitsPerSecond: 1, CostUnits: 10}
	warmRequest := Request{TenantID: uuid.NewString(), RouteID: "safe.read", RequestID: uuid.NewString(), Policy: policy}
	if decision, err := directLimiter.Allow(ctx, warmRequest); err != nil || !decision.Allowed {
		t.Fatalf("warm Redis Lua script cache = %+v, err=%v", decision, err)
	}

	proxy := newRedisEVALSHAReplyDropProxy(t, options.Addr)
	proxyOptions := *options
	proxyOptions.Addr = proxy.addr
	proxyOptions.MaxRetries = -1
	proxyClient := redis.NewClient(&proxyOptions)
	t.Cleanup(func() { _ = proxyClient.Close() })
	if err := proxyClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect through Redis TCP proxy: %v", err)
	}
	proxyLimiter, err := New(proxyClient, limiterConfig)
	if err != nil {
		t.Fatal("create fault-proxied limiter")
	}

	request := Request{TenantID: uuid.NewString(), RouteID: "safe.read", RequestID: uuid.NewString(), Policy: policy}
	if decision, err := proxyLimiter.Allow(ctx, request); err == nil {
		t.Fatalf("fault proxy unexpectedly returned admission decision %+v", decision)
	} else if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost Redis reply classified as %v, want ErrUnavailable", err)
	}
	select {
	case <-proxy.replyDropped:
	case <-ctx.Done():
		t.Fatal("TCP proxy did not observe and drop the committed EVALSHA response")
	}

	replay, err := directLimiter.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != 0 {
		t.Fatalf("exact request retry did not replay the committed Redis decision: %+v, err=%v", replay, err)
	}
	distinct := request
	distinct.RequestID = uuid.NewString()
	decision, err := directLimiter.Allow(ctx, distinct)
	if err != nil || decision.Allowed {
		t.Fatalf("ambiguous committed request did not leave the shared bucket spent: %+v, err=%v", decision, err)
	}
}

func TestReadRedisCommandPreservesRESPAndNormalizesName(t *testing.T) {
	frame := "*2\r\n$7\r\nevalsha\r\n$3\r\nabc\r\n"
	gotFrame, command, err := readRedisCommand(bufio.NewReader(strings.NewReader(frame)))
	if err != nil {
		t.Fatalf("read RESP command: %v", err)
	}
	if string(gotFrame) != frame || command != "EVALSHA" {
		t.Fatalf("parsed frame=%q command=%q; want original frame and EVALSHA", gotFrame, command)
	}
}

func TestReadRedisCommandRejectsMalformedFrame(t *testing.T) {
	for _, frame := range []string{"PING\r\n", "*0\r\n", "*1\r\n$4\r\nPINGx", "*1\r\n$-1\r\n"} {
		if _, _, err := readRedisCommand(bufio.NewReader(strings.NewReader(frame))); err == nil {
			t.Errorf("accepted malformed command frame %q", frame)
		}
	}
}

type redisEVALSHAReplyDropProxy struct {
	addr         string
	replyDropped chan struct{}
	dropNext     atomic.Bool
}

func newRedisEVALSHAReplyDropProxy(t *testing.T, upstream string) *redisEVALSHAReplyDropProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for Redis fault proxy")
	}
	proxy := &redisEVALSHAReplyDropProxy{addr: listener.Addr().String(), replyDropped: make(chan struct{})}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.handleConnection(clientConn, upstream)
		}
	}()
	return proxy
}

func (p *redisEVALSHAReplyDropProxy) handleConnection(clientConn net.Conn, upstream string) {
	upstreamConn, err := net.DialTimeout("tcp", upstream, time.Second)
	if err != nil {
		_ = clientConn.Close()
		return
	}
	defer clientConn.Close()
	defer upstreamConn.Close()
	clientReader := bufio.NewReader(clientConn)
	upstreamReader := bufio.NewReader(upstreamConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			frame, command, err := readRedisCommand(clientReader)
			if err != nil {
				return
			}
			if command == "EVALSHA" {
				p.dropNext.Store(true)
			}
			if err := writeRedisFrame(upstreamConn, frame); err != nil {
				return
			}
		}
	}()

	for {
		responseByte, err := upstreamReader.ReadByte()
		if err != nil {
			return
		}
		if p.dropNext.CompareAndSwap(true, false) {
			close(p.replyDropped)
			return
		}
		if err := writeRedisFrame(clientConn, []byte{responseByte}); err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func readRedisCommand(reader *bufio.Reader) ([]byte, string, error) {
	frame := &bytes.Buffer{}
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, "", err
	}
	if len(line) < 3 || line[0] != '*' || !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, "", errors.New("invalid Redis command array")
	}
	frame.Write(line)
	count, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")[1:])
	if err != nil || count < 1 || count > 1024 {
		return nil, "", errors.New("invalid Redis command length")
	}
	command := ""
	for i := 0; i < count; i++ {
		header, err := reader.ReadBytes('\n')
		if err != nil || len(header) < 3 || header[0] != '$' || !bytes.HasSuffix(header, []byte("\r\n")) {
			return nil, "", errors.New("invalid Redis command bulk header")
		}
		frame.Write(header)
		length, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(string(header), "\n"), "\r")[1:])
		if err != nil || length < 0 || length > 1<<20 {
			return nil, "", errors.New("invalid Redis command bulk length")
		}
		argument := make([]byte, length+2)
		if _, err := io.ReadFull(reader, argument); err != nil {
			return nil, "", err
		}
		if !bytes.HasSuffix(argument, []byte("\r\n")) {
			return nil, "", errors.New("invalid Redis command bulk terminator")
		}
		frame.Write(argument)
		if i == 0 {
			command = strings.ToUpper(string(argument[:length]))
		}
	}
	return frame.Bytes(), command, nil
}

func writeRedisFrame(writer io.Writer, frame []byte) error {
	for len(frame) > 0 {
		written, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}
