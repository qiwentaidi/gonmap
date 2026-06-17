package simplenet

import (
	"encoding/binary"
	"io"
	"net"
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

func TestSendPostgresStartupWithoutSSL(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
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
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil {
			serverErr <- err
			return
		}
		if got := binary.BigEndian.Uint32(header[:4]); got < 8 {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		if got := binary.BigEndian.Uint32(header[4:8]); got != 196608 {
			t.Errorf("expected protocol 196608, got %d", got)
		}

		remaining := int(binary.BigEndian.Uint32(header[:4])) - len(header)
		payload := make([]byte, remaining)
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverErr <- err
			return
		}
		text := string(payload)
		if !strings.Contains(text, "user\x00system\x00") {
			t.Errorf("expected startup packet to include system user, got %q", text)
		}
		if !strings.Contains(text, "database\x00system\x00") {
			t.Errorf("expected startup packet to include system database, got %q", text)
		}
		if !strings.Contains(text, "client_encoding\x00UTF8\x00") {
			t.Errorf("expected startup packet to include UTF8 client encoding, got %q", text)
		}

		_, err = conn.Write([]byte("R\x00\x00\x00\x08\x00\x00\x00\x03"))
		serverErr <- err
	}()

	text, err := SendPostgresStartup(listener.Addr().String(), time.Second, 256, false, "")
	if err != nil {
		t.Fatalf("expected startup probe to succeed, got %v", err)
	}
	if text != "R\x00\x00\x00\x08\x00\x00\x00\x03" {
		t.Fatalf("unexpected response %q", text)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
}
