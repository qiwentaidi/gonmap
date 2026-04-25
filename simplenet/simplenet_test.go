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

func TestSplitNetlocHost(t *testing.T) {
	tests := []struct {
		name   string
		netloc string
		want   string
	}{
		{name: "ipv4", netloc: "127.0.0.1:443", want: "127.0.0.1"},
		{name: "ipv6", netloc: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "hostname", netloc: "example.com:443", want: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitNetlocHost(tt.netloc)
			if got != tt.want {
				t.Fatalf("expected host %q, got %q", tt.want, got)
			}
		})
	}
}
