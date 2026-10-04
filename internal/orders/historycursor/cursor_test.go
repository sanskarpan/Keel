package historycursor

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const (
	testTenant = "11111111-1111-4111-8111-111111111111"
	testOrder  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestCursorIsOpaqueAndBoundToTenantOrderAndPageSize(t *testing.T) {
	codec := testCodec(t, "key-a", bytes.Repeat([]byte{1}, 32))
	token, err := codec.Encode(testTenant, testOrder, 7, 25)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, testTenant) || strings.Contains(token, testOrder) {
		t.Fatal("cursor exposed its tenant or order scope")
	}
	if before, err := codec.Decode(token, testTenant, testOrder, 25); err != nil || before != 7 {
		t.Fatalf("decoded before=%d err=%v, want version 7", before, err)
	}
	for name, args := range map[string]struct {
		tenant string
		order  string
		limit  int
	}{
		"other tenant": {tenant: "22222222-2222-4222-8222-222222222222", order: testOrder, limit: 25},
		"other order":  {tenant: testTenant, order: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", limit: 25},
		"other limit":  {tenant: testTenant, order: testOrder, limit: 10},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := codec.Decode(token, args.tenant, args.order, args.limit); err == nil {
				t.Fatal("cursor decoded outside its bound scope")
			}
		})
	}
}

func TestCursorTamperingExpiryAndKeyRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{3}, 32)
	newKey := bytes.Repeat([]byte{4}, 32)
	oldCodec := testCodec(t, "old", oldKey)
	token, err := oldCodec.Encode(testTenant, testOrder, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := New("new", map[string][]byte{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	if before, err := rotated.Decode(token, testTenant, testOrder, 2); err != nil || before != 4 {
		t.Fatalf("old-key cursor before=%d err=%v", before, err)
	}
	parts := strings.Split(token, ".")
	last := parts[2][0]
	parts[2] = map[bool]string{true: "A", false: "B"}[last != 'A'] + parts[2][1:]
	changed := strings.Join(parts, ".")
	if _, err := rotated.Decode(changed, testTenant, testOrder, 2); err == nil {
		t.Fatal("tampered cursor was accepted")
	}
	rotated.now = func() time.Time { return time.Now().Add(defaultLifetime + time.Second) }
	if _, err := rotated.Decode(token, testTenant, testOrder, 2); err == nil {
		t.Fatal("expired cursor was accepted")
	}
}

func TestNewRequiresActiveAES256Key(t *testing.T) {
	if _, err := New("missing", map[string][]byte{}); err == nil {
		t.Fatal("missing active key was accepted")
	}
	if _, err := New("active", map[string][]byte{"active": []byte("too short")}); err == nil {
		t.Fatal("short key was accepted")
	}
}

func testCodec(t *testing.T, keyID string, key []byte) *Codec {
	t.Helper()
	codec, err := New(keyID, map[string][]byte{keyID: key})
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
