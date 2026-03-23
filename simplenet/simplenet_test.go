package simplenet

import (
	"strings"
	"testing"
	"time"
)

func TestSendRejectsUDPProxy(t *testing.T) {
	_, err := Send("UDP", false, "1.1.1.1:53", "", time.Second, 128, "socks5://127.0.0.1:1080")
	if err == nil {
		t.Fatal("expected error for UDP over SOCKS5 proxy")
	}
	if !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("expected UDP-related error, got %v", err)
	}
}
