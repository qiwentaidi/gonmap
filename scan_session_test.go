package gonmap

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNormalizeScanOptionsDefaults(t *testing.T) {
	engine := New()

	options := engine.normalizeScanOptions(nil)
	if options.Timeout != defaultScanTimeout {
		t.Fatalf("expected default timeout %v, got %v", defaultScanTimeout, options.Timeout)
	}
	if options.ReadSize != defaultReadSize {
		t.Fatalf("expected default read size %d, got %d", defaultReadSize, options.ReadSize)
	}
	if options.Protocol != ScanProtocolAuto {
		t.Fatalf("expected default protocol %q, got %q", ScanProtocolAuto, options.Protocol)
	}
	if options.DisableFingerprint {
		t.Fatal("expected disable fingerprint to be disabled by default")
	}
}

func TestScanOpenOnlyReturnsOpenForListeningTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(done)
	}()

	engine := New()
	status, response := engine.ScanWithOptions("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &ScanOptions{
		Timeout:            200 * time.Millisecond,
		Protocol:           ScanProtocolTCP,
		DisableFingerprint: true,
	})
	if status != Open {
		t.Fatalf("expected open status, got %v", status)
	}
	if response != nil {
		t.Fatalf("expected nil response when fingerprint is disabled, got %#v", response)
	}
	<-done
}

func TestScanChecksClosedTCPBeforeResolvingProbes(t *testing.T) {
	engine := New()
	engine.allProbeMap = nil
	engine.sslProbeMap = nil
	engine.portProbeMap[1] = nil

	status, response := engine.ScanWithOptions("127.0.0.1", 1, &ScanOptions{
		Timeout:  100 * time.Millisecond,
		Protocol: ScanProtocolTCP,
	})
	if status != Closed {
		t.Fatalf("expected closed status, got %v", status)
	}
	if response != nil {
		t.Fatalf("expected nil response for closed port, got %#v", response)
	}
}

func TestResolveProbeNamesFiltersByProtocol(t *testing.T) {
	engine := New()

	udpSession := newScanSession(engine, "127.0.0.1", 53, engine.normalizeScanOptions(&ScanOptions{
		Protocol: ScanProtocolUDP,
	}))
	udpProbes := udpSession.resolveProbeNames()
	if len(udpProbes) == 0 {
		t.Fatal("expected UDP probes for port 53")
	}
	for _, probeName := range udpProbes {
		if len(probeName) < 4 || probeName[:4] != "UDP_" {
			t.Fatalf("expected UDP probe, got %q", probeName)
		}
	}

	tcpSession := newScanSession(engine, "127.0.0.1", 80, engine.normalizeScanOptions(&ScanOptions{
		Protocol: ScanProtocolTCP,
	}))
	tcpProbes := tcpSession.resolveProbeNames()
	if len(tcpProbes) == 0 {
		t.Fatal("expected TCP probes for port 80")
	}
	for _, probeName := range tcpProbes {
		if len(probeName) < 4 || probeName[:4] != "TCP_" {
			t.Fatalf("expected TCP probe, got %q", probeName)
		}
	}
}

func TestProbeScanUsesJoinHostPortForIPv6(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 loopback not available: %v", err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			accepted <- err
			return
		}
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			accepted <- err
			return
		}
		expected := fmt.Sprintf("ping [::1]:%d", listener.Addr().(*net.TCPAddr).Port)
		if string(buf[:n]) != expected {
			accepted <- fmt.Errorf("expected payload %q, got %q", expected, string(buf[:n]))
			return
		}
		_, err = conn.Write([]byte("pong"))
		accepted <- err
	}()

	p := &probe{
		protocol: "TCP",
		sendRaw:  "ping {Host}",
	}
	port := listener.Addr().(*net.TCPAddr).Port
	text, _, err := p.scan("::1", port, false, time.Second, 128, "")
	if err != nil {
		t.Fatalf("expected ipv6 scan to succeed, got %v", err)
	}
	if text != "pong" {
		t.Fatalf("expected pong response, got %q", text)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
}
