package gonmap

import (
	"fmt"
	"net"
	"strings"
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

func TestScanMatchesElasticsearchProductWhileKeepingHTTPService(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	response := strings.Join([]string{
		"HTTP/1.1 401 Unauthorized",
		"Content-Length: 405",
		"Connection: keep-alive",
		"Content-Type: application/json",
		"Keep-Alive: timeout=4",
		"Proxy-Connection: keep-alive",
		`Www-Authenticate: Basic realm="security", charset="UTF-8"`,
		"Www-Authenticate: ApiKey",
		"",
		`{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials for REST request [/]","header":{"WWW-Authenticate":["Basic realm=\"security\", charset=\"UTF-8\"","ApiKey"]}}],"type":"security_exception","reason":"missing authentication credentials for REST request [/]","header":{"WWW-Authenticate":["Basic realm=\"security\", charset=\"UTF-8\"","ApiKey"]}},"status":401}`,
	}, "\r\n")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	engine := New()
	status, resp := engine.ScanWithOptions("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &ScanOptions{
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
		ReadSize: 4096,
	})

	if status != Matched {
		t.Fatalf("expected matched status, got %v", status)
	}
	if resp == nil || resp.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", resp)
	}
	if resp.TLS {
		t.Fatalf("expected plaintext http match, got tls response: %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "http" {
		t.Fatalf("expected service http, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "Elasticsearch" {
		t.Fatalf("expected product Elasticsearch, got %q", product)
	}
}

func TestScanMatchesElasticsearchVersionFromXElasticProductHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	response := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"X-Elastic-Product: Elasticsearch",
		"Content-Type: application/json; charset=UTF-8",
		"Content-Length: 327",
		"",
		`{"name":"node-1","cluster_name":"docker-cluster","cluster_uuid":"abc123","version":{"number":"8.13.4","build_flavor":"default","build_type":"docker","build_hash":"deadbeef","build_date":"2024-01-01T00:00:00.000Z","build_snapshot":false,"lucene_version":"9.10.0"},"tagline":"You Know, for Search"}`,
	}, "\r\n")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	engine := New()
	status, resp := engine.ScanWithOptions("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &ScanOptions{
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
		ReadSize: 4096,
	})

	if status != Matched {
		t.Fatalf("expected matched status, got %v", status)
	}
	if resp == nil || resp.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "http" {
		t.Fatalf("expected service http, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "Elasticsearch" {
		t.Fatalf("expected product Elasticsearch, got %q", product)
	}
	if version := resp.FingerPrint.Version; version != "8.13.4" {
		t.Fatalf("expected version 8.13.4, got %q", version)
	}
}

func TestScanMatchesOpenSearchWithoutChangingHTTPService(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	response := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/json; charset=UTF-8",
		"Content-Length: 352",
		"",
		`{"name":"opensearch-node1","cluster_name":"opensearch-cluster","cluster_uuid":"xyz987","version":{"distribution":"opensearch","number":"2.14.0","build_type":"tar","build_hash":"cafebabe","build_date":"2024-02-02T00:00:00.000Z","build_snapshot":false,"lucene_version":"9.10.0","minimum_wire_compatibility_version":"7.10.0","minimum_index_compatibility_version":"7.0.0"},"tagline":"The OpenSearch Project: https://opensearch.org/"}`,
	}, "\r\n")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	engine := New()
	status, resp := engine.ScanWithOptions("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &ScanOptions{
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
		ReadSize: 4096,
	})

	if status != Matched {
		t.Fatalf("expected matched status, got %v", status)
	}
	if resp == nil || resp.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "http" {
		t.Fatalf("expected service http, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "OpenSearch" {
		t.Fatalf("expected product OpenSearch, got %q", product)
	}
	if version := resp.FingerPrint.Version; version != "2.14.0" {
		t.Fatalf("expected version 2.14.0, got %q", version)
	}
}

func TestEnrichFingerprintByPortMarksKingbaseOnDefaultPort(t *testing.T) {
	fp := &FingerPrint{
		Service:     "postgresql",
		ProductName: "PostgreSQL DB",
	}

	enrichFingerprintByPort(54321, fp)

	if fp.Service != "kingbase" {
		t.Fatalf("expected service to become kingbase, got %q", fp.Service)
	}
	if fp.ProductName != "KingbaseES" {
		t.Fatalf("expected product KingbaseES, got %q", fp.ProductName)
	}
}

func TestEnrichFingerprintByPortDoesNotRelabelOtherPorts(t *testing.T) {
	fp := &FingerPrint{
		Service:     "postgresql",
		ProductName: "PostgreSQL DB",
	}

	enrichFingerprintByPort(5432, fp)

	if fp.ProductName != "PostgreSQL DB" {
		t.Fatalf("expected product to remain PostgreSQL DB, got %q", fp.ProductName)
	}
}

func TestResolveProbeNamesIncludesPostgreSQLProbesForKingbaseDefaultPort(t *testing.T) {
	engine := New()
	session := newScanSession(engine, "127.0.0.1", 54321, engine.normalizeScanOptions(&ScanOptions{
		Protocol: ScanProtocolTCP,
	}))

	probes := session.resolveProbeNames()
	probeSet := make(map[string]struct{}, len(probes))
	for _, probeName := range probes {
		probeSet[probeName] = struct{}{}
	}

	if _, ok := probeSet["TCP_GenericLines"]; !ok {
		t.Fatalf("expected TCP_GenericLines probe for port 54321, got %#v", probes)
	}
	if _, ok := probeSet["TCP_SMBProgNeg"]; !ok {
		t.Fatalf("expected TCP_SMBProgNeg probe for port 54321, got %#v", probes)
	}
	if _, ok := probeSet["TCP_KB_POSTGRES_STARTUP"]; !ok {
		t.Fatalf("expected TCP_KB_POSTGRES_STARTUP probe for port 54321, got %#v", probes)
	}
	if _, ok := probeSet["TCP_KB_POSTGRES_SSL_STARTUP"]; !ok {
		t.Fatalf("expected TCP_KB_POSTGRES_SSL_STARTUP probe for port 54321, got %#v", probes)
	}
}

func TestScanMatchesKingbaseStartupAuthWhileServerKeepsConnectionOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\x00\x00"))
				time.Sleep(1500 * time.Millisecond)
			}(conn)
		}
	}()

	engine := New()
	session := newScanSession(engine, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, engine.normalizeScanOptions(&ScanOptions{
		Timeout:  2 * time.Second,
		Protocol: ScanProtocolTCP,
		ReadSize: 4096,
	}))

	probe := engine.probeNameMap["TCP_KB_POSTGRES_STARTUP"]
	if probe == nil {
		t.Fatal("expected TCP_KB_POSTGRES_STARTUP probe to exist")
	}

	status, resp := session.getResponse(false, probe)

	if status != Matched {
		t.Fatalf("expected matched status, got %v resp=%#v", status, resp)
	}
	if resp == nil || resp.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "postgresql" {
		t.Fatalf("expected service postgresql before port enrichment, got %q", service)
	}
	if probeName := resp.FingerPrint.ProbeName; probeName != "TCP_KB_POSTGRES_STARTUP" {
		t.Fatalf("expected startup probe match, got %q", probeName)
	}
}
