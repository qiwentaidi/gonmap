package gonmap

import "testing"

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
