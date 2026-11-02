package lib

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A local SOCKS server simulates hosts that exist only behind the proxy. It
// never connects to external targets. Every accepted tunnel serves HTTP.
func startHostDiscoveryProxy(t *testing.T, allow func(string, int) bool) (string, func() []string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(conn, greeting); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				var host string
				switch header[3] {
				case 1, 4:
					length := 4
					if header[3] == 4 {
						length = 16
					}
					address := make([]byte, length)
					if _, err := io.ReadFull(conn, address); err != nil {
						return
					}
					host = net.IP(address).String()
				case 3:
					length := make([]byte, 1)
					if _, err := io.ReadFull(conn, length); err != nil {
						return
					}
					address := make([]byte, int(length[0]))
					if _, err := io.ReadFull(conn, address); err != nil {
						return
					}
					host = string(address)
				default:
					return
				}
				portBytes := make([]byte, 2)
				if _, err := io.ReadFull(conn, portBytes); err != nil {
					return
				}
				port := int(binary.BigEndian.Uint16(portBytes))
				mu.Lock()
				requests = append(requests, net.JoinHostPort(host, strconv.Itoa(port)))
				mu.Unlock()
				if !allow(host, port) {
					_, _ = conn.Write([]byte{5, 5, 0, 1, 127, 0, 0, 1, 0, 0})
					return
				}
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				buffer := make([]byte, 2048)
				if n, _ := conn.Read(buffer); n > 0 {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nServer: test-server\r\nContent-Length: 0\r\n\r\n")
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); wg.Wait() })
	return "socks5://" + listener.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}
}

func TestBatchHostDiscoveryFiltersBeforeFullScanAndUsesProxy(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(host string, port int) bool {
		// The quiet host has a service at 8080, but no heuristic port open.
		return port == 8080 || host == "live.invalid"
	})
	sdk := New(&Options{ProxyURL: proxyURL})
	events := 0
	opts := &BatchScanOptions{
		HostDiscovery:      &HostDiscoveryOptions{Ports: []int{80}, Timeout: 300 * time.Millisecond, OnResult: func(HostDiscoveryResult) { events++ }},
		DiscoveryOptions:   PortDiscoveryOptions{Timeout: 300 * time.Millisecond, Concurrency: 4},
		FingerprintOptions: ScanOptions{Timeout: 500 * time.Millisecond, Protocol: ScanProtocolTCP},
	}
	results := sdk.ScanHostsPorts([]string{"quiet.invalid", "live.invalid", "live.invalid"}, []int{8080}, opts)
	if len(results) != 2 || events != 2 {
		t.Fatalf("unexpected result/callback count: %+v events=%d", results, events)
	}
	if results[0].HostDiscovery.Status != HostUnconfirmed || len(results[0].OpenPorts) != 0 {
		t.Fatalf("unconfirmed host was scanned: %+v", results[0])
	}
	if results[1].HostDiscovery.Status != HostConfirmed || results[1].HostDiscovery.Port != 80 || !reflect.DeepEqual(results[1].OpenPorts, []int{8080}) {
		t.Fatalf("live host did not reach configured scan range: %+v", results[1])
	}
	if len(results[1].Results) != 1 || results[1].Results[0].Status != Matched || results[1].Results[0].Response.FingerPrint.Service != "http" {
		t.Fatalf("fingerprint did not traverse proxy: %+v", results[1].Results)
	}
	fullConnections := 0
	for _, request := range requests() {
		if request == "quiet.invalid:8080" {
			t.Fatal("unconfirmed host entered full scan queue")
		}
		if request == "live.invalid:8080" {
			fullConnections++
		}
	}
	if fullConnections < 2 {
		t.Fatalf("expected both discovery and fingerprint via proxy: %v", requests())
	}
	if opts.HostDiscovery.ProxyURL != "" || opts.DiscoveryOptions.ProxyURL != "" || opts.FingerprintOptions.ProxyURL != "" {
		t.Fatal("batch mutated caller options")
	}
}

func TestBatchHostDiscoveryOptInAndExplicitProxy(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(_ string, port int) bool { return port == 8080 })
	sdk := New(&Options{ProxyURL: proxyURL, DisableFingerprint: true})
	result := sdk.ScanHostPorts("quiet.invalid", []int{8080}, &BatchScanOptions{})
	if result.HostDiscovery != nil || !reflect.DeepEqual(result.OpenPorts, []int{8080}) {
		t.Fatalf("disabled heuristic changed host admission: %+v", result)
	}
	for _, request := range requests() {
		if request != "quiet.invalid:8080" {
			t.Fatalf("disabled heuristic sent probe: %s", request)
		}
	}
	// An explicit per-call proxy must override the SDK proxy for all phases.
	sdk = New(&Options{ProxyURL: "socks5://127.0.0.1:1", DisableFingerprint: true})
	result = sdk.ScanHostPorts("live.invalid", []int{8080}, &BatchScanOptions{
		HostDiscovery: &HostDiscoveryOptions{Ports: []int{8080}, ProxyURL: proxyURL},
	})
	if result.HostDiscovery.Status != HostConfirmed || len(result.OpenPorts) != 1 {
		t.Fatalf("explicit transport override failed: %+v", result)
	}
}

func TestBatchHostDiscoveryRejectsInvalidConfigBeforeNetwork(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(string, int) bool { return true })
	sdk := New(&Options{ProxyURL: proxyURL})
	for i, opts := range []BatchScanOptions{
		{HostDiscovery: &HostDiscoveryOptions{Ports: []int{0}}},
		{HostDiscovery: &HostDiscoveryOptions{}, DiscoveryOptions: PortDiscoveryOptions{Mode: PortDiscoveryModeSYN}},
		{HostDiscovery: &HostDiscoveryOptions{}, FingerprintOptions: ScanOptions{Protocol: ScanProtocolUDP}},
		{HostDiscovery: &HostDiscoveryOptions{ProxyURL: proxyURL}, FingerprintOptions: ScanOptions{ProxyURL: "socks5://127.0.0.1:1"}},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := sdk.ScanHostPorts("live.invalid", []int{8080}, &opts)
			if result.HostDiscovery.Status != HostProbeError || result.HostDiscovery.Error == "" {
				t.Fatalf("missing config diagnostic: %+v", result)
			}
		})
	}
	if len(requests()) != 0 {
		t.Fatalf("invalid config generated traffic: %v", requests())
	}
}

func TestBatchHostDiscoveryCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := New(nil).ScanHostsPortsWithContext(ctx, []string{"127.0.0.1", "::1"}, []int{80, 443}, &BatchScanOptions{HostDiscovery: &HostDiscoveryOptions{}})
	if len(results) != 2 {
		t.Fatalf("cancellation lost host diagnostics: %+v", results)
	}
	for _, result := range results {
		if result.HostDiscovery.Status != HostCanceled || len(result.Results) != 0 {
			t.Fatalf("canceled preflight entered scan: %+v", result)
		}
	}
}

func TestSDKHostDiscoveryInheritsProxy(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(string, int) bool { return true })
	results, err := New(&Options{ProxyURL: proxyURL}).DiscoverLiveHosts([]string{"remote.invalid"}, &HostDiscoveryOptions{Ports: []int{443}})
	if err != nil || len(results) != 1 || results[0].Status != HostConfirmed || !reflect.DeepEqual(requests(), []string{"remote.invalid:443"}) {
		t.Fatalf("SDK did not inherit proxy: %+v %v %v", results, err, requests())
	}
}

func TestBatchHostDiscoveryCancellationAfterConfirmationStopsFullScan(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(string, int) bool { return true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := New(&Options{ProxyURL: proxyURL}).ScanHostsPortsWithContext(ctx, []string{"live.invalid"}, []int{8080}, &BatchScanOptions{
		HostDiscovery: &HostDiscoveryOptions{Ports: []int{80}, OnResult: func(HostDiscoveryResult) { cancel() }},
	})
	if ctx.Err() == nil || len(results) != 1 || results[0].HostDiscovery.Status != HostConfirmed || len(results[0].Results) != 0 {
		t.Fatalf("incorrect partial results after cancellation: %+v", results)
	}
	if !reflect.DeepEqual(requests(), []string{"live.invalid:80"}) {
		t.Fatalf("canceled task entered full scan: %v", requests())
	}
}
