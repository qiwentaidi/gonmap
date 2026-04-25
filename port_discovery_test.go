package gonmap

import (
	"net"
	"testing"
	"time"
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
