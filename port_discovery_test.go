package gonmap

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestExpandPortRange(t *testing.T) {
	ports := ExpandPortRange(1, 3)
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	if ports[0] != 1 || ports[1] != 2 || ports[2] != 3 {
		t.Fatalf("unexpected ports: %#v", ports)
	}
}

func TestDiscoverOpenPortsFindsListeningSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	results := DiscoverOpenPorts([]string{"127.0.0.1"}, []int{port, port + 1}, &PortDiscoveryOptions{
		Timeout:     200 * time.Millisecond,
		Concurrency: 8,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %#v", results)
	}
	if results[0].Host != "127.0.0.1" || results[0].Port != port {
		t.Fatalf("unexpected result: %#v", results[0])
	}
}

func TestDiscoverOpenPortsSYNDoesNotFallBackToConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	originalOpenSYNRawConn := openSYNRawConn
	openSYNRawConn = func() (*ipv4.RawConn, error) {
		return nil, errors.New("raw socket unavailable")
	}
	t.Cleanup(func() {
		openSYNRawConn = originalOpenSYNRawConn
	})

	port := listener.Addr().(*net.TCPAddr).Port
	output := captureStderr(t, func() {
		results := DiscoverOpenPorts([]string{"127.0.0.1"}, []int{port, port + 1}, &PortDiscoveryOptions{
			Timeout:     200 * time.Millisecond,
			Concurrency: 8,
			Mode:        PortDiscoveryModeSYN,
		})

		if len(results) != 0 {
			t.Fatalf("expected no results when syn is unavailable, got %#v", results)
		}
	})

	if !strings.Contains(output, "syn discovery failed: raw socket unavailable") {
		t.Fatalf("expected syn discovery error in stderr, got %q", output)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	originalStderr := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	os.Stderr = writePipe
	defer func() {
		os.Stderr = originalStderr
	}()

	fn()

	if err := writePipe.Close(); err != nil {
		t.Fatalf("failed to close stderr pipe: %v", err)
	}
	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("failed to read stderr: %v", err)
	}
	if err := readPipe.Close(); err != nil {
		t.Fatalf("failed to close stderr read pipe: %v", err)
	}
	return string(output)
}
