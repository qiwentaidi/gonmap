package gonmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostDiscoveryDefaultsOrderAndDeduplication(t *testing.T) {
	opts, err := normalizeHostDiscoveryOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	addresses := make(map[string][]string)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || network != "tcp" {
			t.Errorf("invalid TCP destination: %s %s %v", network, address, err)
		}
		mu.Lock()
		addresses[host] = append(addresses[host], port)
		mu.Unlock()
		return nil, errors.New("connection refused")
	}
	results, err := discoverLiveHosts(context.Background(), []string{" host.test ", "::1", "host.test", ""}, opts, dial)
	if err != nil || len(results) != 2 || results[0].Host != "host.test" || results[1].Host != "::1" {
		t.Fatalf("unstable results: %+v %v", results, err)
	}
	for _, result := range results {
		if result.Status != HostUnconfirmed || result.Port != 0 {
			t.Fatalf("a refused connection must not confirm liveness: %+v", result)
		}
		ports := addresses[result.Host]
		sort.Strings(ports)
		if !reflect.DeepEqual(ports, []string{"22", "3389", "443", "445", "80"}) {
			t.Fatalf("unexpected default probes: %v", ports)
		}
	}
	defaults := DefaultTCPHostDiscoveryPorts()
	defaults[0] = 1234
	if DefaultTCPHostDiscoveryPorts()[0] != 80 {
		t.Fatal("default ports shared mutable state")
	}
}

func TestHostDiscoveryConnectsWithoutSendingFingerprint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	read := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			read <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		_, err = conn.Read(buffer)
		read <- err
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	results, err := DiscoverLiveHostsWithContext(nil, []string{"127.0.0.1"}, &HostDiscoveryOptions{Ports: []int{port, port}})
	if err != nil || len(results) != 1 || results[0].Status != HostConfirmed || results[0].Port != port {
		t.Fatalf("expected live socket: %+v %v", results, err)
	}
	if err := <-read; !errors.Is(err, io.EOF) {
		t.Fatalf("probe should close without sending data: %v", err)
	}
}

func TestHostDiscoveryFirstSuccessCancelsOtherProbes(t *testing.T) {
	opts, _ := normalizeHostDiscoveryOptions(&HostDiscoveryOptions{Ports: []int{80, 443, 22, 3389, 445}, PortsPerHost: 2, Concurrency: 2})
	otherStarted := make(chan struct{})
	var calls, active atomic.Int32
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		if strings.HasSuffix(address, ":80") {
			select {
			case <-otherStarted:
				conn, peer := net.Pipe()
				_ = peer.Close()
				return conn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		close(otherStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	results, err := discoverLiveHosts(context.Background(), []string{"host.test"}, opts, dial)
	if err != nil || results[0].Status != HostConfirmed || results[0].Port != 80 || calls.Load() != 2 || active.Load() != 0 {
		t.Fatalf("first match did not stop and join probes: %+v err=%v calls=%d active=%d", results, err, calls.Load(), active.Load())
	}
}

func TestHostDiscoveryGlobalBudgetAndTimeout(t *testing.T) {
	opts, _ := normalizeHostDiscoveryOptions(&HostDiscoveryOptions{Ports: []int{80, 443}, Concurrency: 3, Timeout: 10 * time.Millisecond})
	var active, peak, calls atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	hosts := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	events := 0
	opts.OnResult = func(result HostDiscoveryResult) {
		events++
		if result.Status != HostUnconfirmed {
			t.Errorf("timeout is not offline/confirmed: %+v", result)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results, err := discoverLiveHosts(ctx, hosts, opts, dial)
	if err != nil || len(results) != len(hosts) || calls.Load() != 16 || events != len(hosts) || peak.Load() > 3 || active.Load() != 0 {
		t.Fatalf("budget/timeout violation: err=%v results=%d calls=%d events=%d peak=%d active=%d", err, len(results), calls.Load(), events, peak.Load(), active.Load())
	}
}

func TestHostDiscoveryCancellationJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	opts, _ := normalizeHostDiscoveryOptions(&HostDiscoveryOptions{Concurrency: 3, Timeout: time.Minute})
	var active, started atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		active.Add(1)
		defer active.Add(-1)
		if started.Add(1) == 3 {
			cancel()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	hosts := make([]string, 50)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host-%d", i)
	}
	results, err := discoverLiveHosts(ctx, hosts, opts, dial)
	if !errors.Is(err, context.Canceled) || active.Load() != 0 || started.Load() != 3 || len(results) != len(hosts) {
		t.Fatalf("cancellation did not drain: err=%v active=%d started=%d results=%d", err, active.Load(), started.Load(), len(results))
	}
	for _, result := range results {
		if result.Status != HostCanceled || result.Error == "" {
			t.Fatalf("canceled target must not be reported unconfirmed: %+v", result)
		}
	}
}

func TestHostDiscoveryRejectsInvalidConfiguration(t *testing.T) {
	for _, opts := range []HostDiscoveryOptions{
		{Ports: []int{0}}, {Ports: []int{65536}}, {Concurrency: -1}, {Timeout: -1}, {PortsPerHost: -1},
		{ProxyURL: "http://localhost:8080"}, {ProxyURL: "socks5://localhost"}, {ProxyURL: "socks5://localhost:65536"},
	} {
		if _, err := DiscoverLiveHosts([]string{"127.0.0.1"}, &opts); err == nil {
			t.Errorf("accepted invalid options: %+v", opts)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := DiscoverLiveHostsWithContext(ctx, []string{"127.0.0.1", "::1"}, nil)
	if !errors.Is(err, context.Canceled) || len(results) != 2 || results[0].Status != HostCanceled || results[1].Status != HostCanceled {
		t.Fatalf("pre-canceled results: %+v %v", results, err)
	}
}

func TestHostDiscoverySOCKSHandshakeHasDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		// Never answer the SOCKS greeting; cancellation must close the socket.
		_, _ = io.Copy(io.Discard, conn)
	}()
	started := time.Now()
	results, err := DiscoverLiveHosts([]string{"only-through-proxy.invalid"}, &HostDiscoveryOptions{
		Ports: []int{80}, ProxyURL: "socks5://" + listener.Addr().String(), Timeout: 40 * time.Millisecond,
	})
	if err != nil || results[0].Status != HostUnconfirmed || time.Since(started) > time.Second {
		t.Fatalf("proxy timeout failed: %+v %v", results, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timed-out proxy connection leaked")
	}
}
