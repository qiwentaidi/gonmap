package lib

import (
	"fmt"
	"net"
	"testing"
	"time"
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
