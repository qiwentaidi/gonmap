package lib

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/qiwentaidi/gonmap"
)

func TestScanHostPortsDiscoversAndIdentifiesHTTP(t *testing.T) {
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
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: test-server\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	sdk := New(nil)
	result := sdk.ScanHostPorts("127.0.0.1", []int{port, port + 1}, &BatchScanOptions{
		DiscoveryOptions: PortDiscoveryOptions{
			Timeout:     200 * time.Millisecond,
			Concurrency: 16,
		},
		FingerprintOptions: ScanOptions{
			Timeout:  500 * time.Millisecond,
			Protocol: ScanProtocolTCP,
		},
		FingerprintWorkers: 8,
	})

	if len(result.OpenPorts) != 1 || result.OpenPorts[0] != port {
		t.Fatalf("unexpected open ports: %#v", result.OpenPorts)
	}
	if result.LikelyNoise {
		t.Fatalf("expected localhost result not to be marked as noise: %#v", result)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected one result, got %#v", result.Results)
	}
	if result.Results[0].Status != Matched {
		t.Fatalf("expected matched status, got %v", result.Results[0].Status)
	}
	if result.Results[0].Response == nil || result.Results[0].Response.FingerPrint == nil {
		t.Fatalf("expected fingerprint response, got %#v", result.Results[0].Response)
	}
	if service := result.Results[0].Response.FingerPrint.Service; service != "http" {
		t.Fatalf("expected http service, got %q", service)
	}
}

func TestScanHostsPortsStartsFingerprintBeforeDiscoveryFinishes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fingerprintStarted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			close(fingerprintStarted)
			_ = conn.Close()
		}
	}()

	item := OpenPort{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	sdk := New(nil)
	results := sdk.scanHostsPortsWithDiscovery(context.Background(), []string{item.Host}, []int{item.Port}, &BatchScanOptions{
		FingerprintOptions: ScanOptions{Timeout: 200 * time.Millisecond, Protocol: ScanProtocolTCP, DisableFingerprint: true},
		FingerprintWorkers: 1,
	}, func(_ context.Context, _ []string, _ []int, _ *PortDiscoveryOptions, onOpen func(OpenPort)) []OpenPort {
		onOpen(item)
		onOpen(item)
		select {
		case <-fingerprintStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("fingerprint did not start while discovery was still running")
		}
		return []OpenPort{item, item}
	})
	if len(results) != 1 || len(results[0].OpenPorts) != 1 || results[0].OpenPorts[0] != item.Port {
		t.Fatalf("unexpected open ports: %#v", results)
	}
	if len(results[0].Results) != 1 {
		t.Fatalf("duplicate discovery should produce one fingerprint: %#v", results[0].Results)
	}
}

func TestScanHostPortsWithContextCancelsFingerprint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	time.AfterFunc(100*time.Millisecond, cancel)

	port := listener.Addr().(*net.TCPAddr).Port
	sdk := New(nil)
	start := time.Now()
	result := sdk.ScanHostPortsWithContext(ctx, "127.0.0.1", []int{port}, &BatchScanOptions{
		DiscoveryOptions: PortDiscoveryOptions{
			Timeout:     200 * time.Millisecond,
			Concurrency: 4,
		},
		FingerprintOptions: ScanOptions{
			Timeout:  5 * time.Second,
			Protocol: ScanProtocolTCP,
		},
		FingerprintWorkers: 1,
	})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("expected cancellation before fingerprint timeout, elapsed=%s result=%#v", elapsed, result)
	}
}

func TestScanHostPortsRespectsSDKFilter(t *testing.T) {
	t.Cleanup(func() {
		gonmap.SetFilter(9)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:5005")
	if err != nil {
		t.Skipf("failed to reserve jdwp test port 5005: %v", err)
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
				n, _ := c.Read(buf)
				if string(buf[:n]) == "JDWP-Handshake" {
					_, _ = c.Write([]byte("JDWP-Handshake"))
				}
			}(conn)
		}
	}()

	options := &BatchScanOptions{
		DiscoveryOptions: PortDiscoveryOptions{
			Timeout:     200 * time.Millisecond,
			Concurrency: 16,
		},
		FingerprintOptions: ScanOptions{
			Timeout:  500 * time.Millisecond,
			Protocol: ScanProtocolTCP,
		},
		FingerprintWorkers: 4,
	}

	lowFilterSDK := New(&Options{
		Filter:   1,
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
	})
	highFilterSDK := New(&Options{
		Filter:   9,
		Timeout:  500 * time.Millisecond,
		Protocol: ScanProtocolTCP,
	})

	lowFilterResult := lowFilterSDK.ScanHostPorts("127.0.0.1", []int{5005}, options)
	highFilterResult := highFilterSDK.ScanHostPorts("127.0.0.1", []int{5005}, options)

	if len(lowFilterResult.OpenPorts) != 1 || lowFilterResult.OpenPorts[0] != 5005 {
		t.Fatalf("expected low-filter scan to discover port 5005, got %#v", lowFilterResult.OpenPorts)
	}
	if len(highFilterResult.OpenPorts) != 1 || highFilterResult.OpenPorts[0] != 5005 {
		t.Fatalf("expected high-filter scan to discover port 5005, got %#v", highFilterResult.OpenPorts)
	}
	if len(lowFilterResult.Results) != 1 || len(highFilterResult.Results) != 1 {
		t.Fatalf("expected both scans to have one fingerprint result, low=%#v high=%#v", lowFilterResult.Results, highFilterResult.Results)
	}

	if lowFilterResult.Results[0].Status == Matched &&
		lowFilterResult.Results[0].Response != nil &&
		lowFilterResult.Results[0].Response.FingerPrint != nil &&
		lowFilterResult.Results[0].Response.FingerPrint.Service == "jdwp" {
		t.Fatalf("expected low filter to exclude the rarity-8 jdwp probe, got %#v", lowFilterResult.Results[0])
	}

	if highFilterResult.Results[0].Status != Matched {
		t.Fatalf("expected high filter to match jdwp, got %#v", highFilterResult.Results[0])
	}
	if highFilterResult.Results[0].Response == nil || highFilterResult.Results[0].Response.FingerPrint == nil {
		t.Fatalf("expected high filter to return fingerprint response, got %#v", highFilterResult.Results[0].Response)
	}
	if service := highFilterResult.Results[0].Response.FingerPrint.Service; service != "jdwp" {
		t.Fatalf("expected jdwp service with high filter, got %q", service)
	}
}

func TestNormalizeBatchScanOptionsKeepsDiscoveryMode(t *testing.T) {
	normalized := normalizeBatchScanOptions(&BatchScanOptions{
		DiscoveryOptions: PortDiscoveryOptions{
			Mode: PortDiscoveryModeSYN,
			Rate: 3000,
		},
	})

	if normalized.discoveryOptions.Mode != PortDiscoveryModeSYN {
		t.Fatalf("expected syn discovery mode, got %q", normalized.discoveryOptions.Mode)
	}
	if normalized.discoveryOptions.Rate != 3000 {
		t.Fatalf("expected syn rate 3000, got %d", normalized.discoveryOptions.Rate)
	}
}

func TestAnalyzeHostBatchResultFlagsSuspiciousHighPortOpenOnly(t *testing.T) {
	results := []BatchPortResult{
		{Port: 10001, Status: Open},
		{Port: 10002, Status: Open},
		{Port: 10003, Status: Open},
		{Port: 10004, Status: Open},
		{Port: 80, Status: Matched, Response: &Response{FingerPrint: &FingerPrint{Service: "http"}}},
	}
	openPorts := []int{80, 10001, 10002, 10003, 10004}
	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 4,
		suspiciousHighPortStart: 10000,
		suspiciousOpenRatio:     0.60,
	})

	if !analyzed.LikelyNoise {
		t.Fatalf("expected host to be marked as likely noise: %#v", analyzed)
	}
	if len(analyzed.SuspiciousPorts) != 4 {
		t.Fatalf("expected four suspicious ports, got %#v", analyzed.SuspiciousPorts)
	}
	if len(analyzed.LikelyWrappedPorts) != 4 {
		t.Fatalf("expected four likely wrapped ports, got %#v", analyzed.LikelyWrappedPorts)
	}
	if len(analyzed.StablePorts) != 1 || analyzed.StablePorts[0] != 80 {
		t.Fatalf("expected low http port to stay stable, got %#v", analyzed.StablePorts)
	}
	for _, item := range analyzed.Results {
		if item.Port == 80 {
			if item.Suspicious {
				t.Fatalf("expected port 80 to stay stable: %#v", item)
			}
			continue
		}
		expected := fmt.Sprintf("generic open without fingerprint on high port")
		if !item.Suspicious || item.SuspiciousReason != expected {
			t.Fatalf("expected suspicious high port, got %#v", item)
		}
		if !item.LikelyWrapped {
			t.Fatalf("expected suspicious high port to also be marked wrapped-like, got %#v", item)
		}
	}
}

func TestAnalyzeHostBatchResultFlagsNotMatchedHighPortWithoutFingerprint(t *testing.T) {
	results := []BatchPortResult{
		{Port: 9997, Status: NotMatched},
		{Port: 443, Status: Matched, Response: &Response{FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"}}},
	}
	openPorts := []int{443, 9997}
	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 2,
		suspiciousHighPortStart: 1024,
		suspiciousOpenRatio:     0.40,
	})

	if len(analyzed.SuspiciousPorts) != 1 || analyzed.SuspiciousPorts[0] != 9997 {
		t.Fatalf("expected only high not-matched port to be suspicious, got %#v", analyzed.SuspiciousPorts)
	}
	if len(analyzed.StablePorts) != 1 || analyzed.StablePorts[0] != 443 {
		t.Fatalf("expected 443 to remain stable, got %#v", analyzed.StablePorts)
	}
}

func TestAnalyzeHostBatchResultFlagsGenericWrappedFingerprintOnHighPort(t *testing.T) {
	results := []BatchPortResult{
		{
			Port:   20000,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http-proxy"},
			},
		},
		{
			Port:   80,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"},
			},
		},
	}
	openPorts := []int{80, 20000}
	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 2,
		suspiciousHighPortStart: 10000,
		suspiciousOpenRatio:     0.40,
	})

	if !analyzed.LikelyNoise {
		t.Fatalf("expected host to be marked likely noise, got %#v", analyzed)
	}
	if len(analyzed.LikelyWrappedPorts) != 1 || analyzed.LikelyWrappedPorts[0] != 20000 {
		t.Fatalf("expected wrapped high port to be isolated, got %#v", analyzed.LikelyWrappedPorts)
	}
	if len(analyzed.StablePorts) != 1 || analyzed.StablePorts[0] != 80 {
		t.Fatalf("expected port 80 to remain stable, got %#v", analyzed.StablePorts)
	}
}

func TestAnalyzeHostBatchResultFlagsGenericTengineHTTPOnHighPort(t *testing.T) {
	results := []BatchPortResult{
		{
			Port:   10080,
			Status: Matched,
			Response: &Response{
				Raw: "HTTP/1.1 410 Gone\r\nServer: Tengine\r\nContent-Length: 0\r\n\r\n",
				FingerPrint: &FingerPrint{
					Service: "http",
				},
			},
		},
		{
			Port:   443,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"},
			},
		},
	}
	openPorts := []int{443, 10080}
	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 2,
		suspiciousHighPortStart: 1024,
		suspiciousOpenRatio:     0.40,
	})

	if len(analyzed.SuspiciousPorts) != 0 {
		t.Fatalf("expected generic tengine port to stay stable, got suspicious %#v", analyzed.SuspiciousPorts)
	}
	if len(analyzed.StablePorts) != 2 {
		t.Fatalf("expected both ports to remain stable, got %#v", analyzed.StablePorts)
	}
}

func TestAnalyzeHostBatchResultFlagsRepeatedGenericHTTPNoise(t *testing.T) {
	results := []BatchPortResult{
		{
			Port:   12000,
			Status: Matched,
			Response: &Response{
				Raw:         "HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
				FingerPrint: &FingerPrint{Service: "http"},
			},
		},
		{
			Port:   12001,
			Status: Matched,
			Response: &Response{
				Raw:         "HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
				FingerPrint: &FingerPrint{Service: "http"},
			},
		},
		{
			Port:   12002,
			Status: Matched,
			Response: &Response{
				Raw:         "HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
				FingerPrint: &FingerPrint{Service: "http"},
			},
		},
		{
			Port:   443,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"},
			},
		},
	}
	openPorts := []int{443, 12000, 12001, 12002}
	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 4,
		suspiciousHighPortStart: 1024,
		suspiciousOpenRatio:     0.40,
	})

	if len(analyzed.SuspiciousPorts) != 3 {
		t.Fatalf("expected repeated generic http ports to be suspicious, got %#v", analyzed.SuspiciousPorts)
	}
	if len(analyzed.StablePorts) != 1 || analyzed.StablePorts[0] != 443 {
		t.Fatalf("expected 443 to remain stable, got %#v", analyzed.StablePorts)
	}
}

func TestAnalyzeHostBatchResultFlagsMassGenericOpenDensity(t *testing.T) {
	results := make([]BatchPortResult, 0, 130)
	openPorts := make([]int, 0, 130)
	for port := 1; port <= 129; port++ {
		results = append(results, BatchPortResult{Port: port, Status: Open})
		openPorts = append(openPorts, port)
	}
	results = append(results, BatchPortResult{
		Port:   443,
		Status: Matched,
		Response: &Response{
			FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"},
		},
	})
	openPorts = append(openPorts, 443)

	analyzed := analyzeHostBatchResult("example", openPorts, results, normalizedBatchScanOptions{
		suspiciousOpenThreshold: 128,
		suspiciousHighPortStart: 1024,
		suspiciousOpenRatio:     0.60,
	})

	if len(analyzed.StablePorts) != 1 || analyzed.StablePorts[0] != 443 {
		t.Fatalf("expected only 443 to remain stable, got %#v", analyzed.StablePorts)
	}
	if len(analyzed.SuspiciousPorts) != 129 {
		t.Fatalf("expected generic open ports to be suspicious, got %d", len(analyzed.SuspiciousPorts))
	}
	for _, item := range analyzed.Results {
		if item.Port == 443 {
			if item.Suspicious {
				t.Fatalf("expected 443 to remain stable, got %#v", item)
			}
			continue
		}
		if item.SuspiciousReason != "generic open without fingerprint on host with abnormal open-port density" {
			t.Fatalf("unexpected suspicious reason for port %d: %#v", item.Port, item)
		}
	}
}

func TestAnalyzeHostResultsSortsInputsAndPreservesClassification(t *testing.T) {
	results := []BatchPortResult{
		{
			Port:   20000,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http-proxy"},
			},
		},
		{
			Port:   80,
			Status: Matched,
			Response: &Response{
				FingerPrint: &FingerPrint{Service: "http", ProductName: "nginx"},
			},
		},
	}
	openPorts := []int{20000, 80}

	analyzed := AnalyzeHostResults("example", openPorts, results, &BatchScanOptions{
		SuspiciousOpenThreshold: 2,
		SuspiciousHighPortStart: 10000,
		SuspiciousOpenRatio:     0.40,
	})

	if len(analyzed.OpenPorts) != 2 || analyzed.OpenPorts[0] != 80 || analyzed.OpenPorts[1] != 20000 {
		t.Fatalf("expected sorted open ports, got %#v", analyzed.OpenPorts)
	}
	if len(analyzed.Results) != 2 || analyzed.Results[0].Port != 80 || analyzed.Results[1].Port != 20000 {
		t.Fatalf("expected sorted results, got %#v", analyzed.Results)
	}
	if !analyzed.LikelyNoise {
		t.Fatalf("expected likely noise host, got %#v", analyzed)
	}
}
