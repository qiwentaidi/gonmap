package gonmap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
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

func TestScanMatchesDockerRegistryOverHTTPSBeforeGenericServerHeader(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("failed to listen tls: %v", err)
	}
	defer listener.Close()

	response := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Server: nginx/1.18.0",
		"Date: Thu, 18 Jun 2026 03:15:30 GMT",
		"Content-Length: 0",
		"Connection: close",
		"Cache-Control: no-cache",
		"Docker-Distribution-Api-Version: registry/2.0",
		"",
		"",
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
	if service := resp.FingerPrint.Service; service != "https" {
		t.Fatalf("expected service https, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "Docker Registry" {
		t.Fatalf("expected product Docker Registry, got %q", product)
	}
	if info := resp.FingerPrint.Info; info != "API 2.0" {
		t.Fatalf("expected info API 2.0, got %q", info)
	}
}

func TestScanRefinesPlainHTTPToHTTPSWhenServerExplicitlyRequiresTLS(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	plainResponse := "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
	tlsResponse := strings.Join([]string{
		"HTTP/1.1 403 Forbidden",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Length: 78",
		"",
		"Forbidden (user=system:anonymous, verb=get, resource=nodes, subresource=proxy)",
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

				buf := make([]byte, 2048)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				payload := buf[:n]
				if len(payload) > 0 && payload[0] == 0x16 {
					tlsConn := tls.Server(&peekConn{Conn: c, reader: bytes.NewReader(payload)}, &tls.Config{
						Certificates: []tls.Certificate{cert},
					})
					defer tlsConn.Close()

					if err := tlsConn.Handshake(); err != nil {
						return
					}
					_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = tlsConn.Read(make([]byte, 2048))
					_, _ = tlsConn.Write([]byte(tlsResponse))
					return
				}

				_, _ = c.Write([]byte(plainResponse))
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
	if !resp.TLS {
		t.Fatalf("expected refined response to use TLS, got %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "https" {
		t.Fatalf("expected service https, got %q", service)
	}
}

func TestScanRefinesWeakDockerMatchWithVersionProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	weakResponse := strings.Join([]string{
		"HTTP/1.0 404 Not Found",
		"Content-Type: application/json",
		"Date: Thu, 18 Jun 2026 03:21:48 GMT",
		"Content-Length: 29",
		"",
		`{"message":"page not found"}`,
	}, "\r\n") + "\n"

	strongResponse := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/json",
		"Job-Name: version",
		"Date: Thu, 18 Jun 2026 03:21:49 GMT",
		"Content-Length: 98",
		"",
		`{"ApiVersion":"1.41","KernelVersion":"5.15.0","Os":"linux","Version":"20.10.24"}`,
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
				buf := make([]byte, 2048)
				n, _ := c.Read(buf)
				request := string(buf[:n])
				if strings.Contains(request, "GET /version HTTP/1.1") {
					_, _ = c.Write([]byte(strongResponse))
					return
				}
				_, _ = c.Write([]byte(weakResponse))
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
	if service := resp.FingerPrint.Service; service != "docker" {
		t.Fatalf("expected service docker, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "Docker remote API" {
		t.Fatalf("expected product Docker remote API, got %q", product)
	}
	if version := resp.FingerPrint.Version; version != "20.10.24" {
		t.Fatalf("expected version 20.10.24, got %q", version)
	}
	if info := resp.FingerPrint.Info; info != "API 1.41; KernelVersion 5.15.0" {
		t.Fatalf("expected Docker version probe info, got %q", info)
	}
}

func TestScanRefinesWeakEtcdMatchWithVersionProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	weakResponse := strings.Join([]string{
		"HTTP/1.0 404 Not Found",
		"Access-Control-Allow-Headers: accept, content-type, authorization",
		"Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE",
		"Access-Control-Allow-Origin: *",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"404 page not found",
	}, "\r\n")

	strongResponse := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/json",
		"Date: Thu, 18 Jun 2026 03:30:00 GMT",
		"Content-Length: 45",
		"",
		`{"etcdserver":"3.5.10","etcdcluster":"3.5.0"}`,
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
				buf := make([]byte, 2048)
				n, _ := c.Read(buf)
				request := string(buf[:n])
				if strings.Contains(request, "GET /version HTTP/1.1") {
					_, _ = c.Write([]byte(strongResponse))
					return
				}
				_, _ = c.Write([]byte(weakResponse))
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
	if service := resp.FingerPrint.Service; service != "etcd-client" {
		t.Fatalf("expected service etcd-client, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "etcd" {
		t.Fatalf("expected product etcd, got %q", product)
	}
	if version := resp.FingerPrint.Version; version != "3.5.10" {
		t.Fatalf("expected version 3.5.10, got %q", version)
	}
	if info := resp.FingerPrint.Info; info != "cluster 3.5.0" {
		t.Fatalf("expected cluster info, got %q", info)
	}
}

func TestScanMatchesKafkaMetadataResponseWithoutRegexFallback(t *testing.T) {
	rawHex := "000167200000000000000003000000020008352e302e302e363400002384ffff000000030008352e302e302e363500002384ffff000000010008352e302e302e363300002384ffff000000030000027b00000009776c616e5f61703336000000000300000000000000000001000000010000000100000001000000010000000000020000000300000001000000030000000100000003000000000001000000020000000100000002000000010000000200000018776c616e5f6576656e747265706f72745f786d79646174610000000003000000000000000000020000000100000002000000010000000200000000000200000001000000010000000100000001000000"
	payload, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

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
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write(payload)
			}(conn)
		}
	}()

	engine := New()
	session := newScanSession(engine, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, engine.normalizeScanOptions(&ScanOptions{
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
		ReadSize: 4096,
	}))

	probe := engine.probeNameMap["TCP_Kafka"]
	if probe == nil {
		t.Fatal("expected TCP_Kafka probe to exist")
	}

	status, resp := session.getResponse(false, probe)

	if status != Matched {
		t.Fatalf("expected matched status, got %v", status)
	}
	if resp == nil || resp.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", resp)
	}
	if service := resp.FingerPrint.Service; service != "kafka" {
		t.Fatalf("expected service kafka, got %q", service)
	}
	if product := resp.FingerPrint.ProductName; product != "Kafka" {
		t.Fatalf("expected product Kafka, got %q", product)
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

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

type peekConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}
