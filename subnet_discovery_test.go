package gonmap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubnetSamplingScopeDedupAndLargeRange(t *testing.T) {
	ctx := context.Background()
	prefixes, err := subnetPrefixes(ctx, []string{"10.0.1.128/25", "10.0.0.0/8", "10.0.0.0/16"}, 131072)
	if err != nil || len(prefixes) != 65536 || prefixes[0].String() != "10.0.0.0/24" || prefixes[len(prefixes)-1].String() != "10.255.255.0/24" {
		t.Fatalf("incorrect partition: %d %v", len(prefixes), err)
	}
	opts := DefaultSubnetDiscoveryOptions()
	p := netip.MustParsePrefix("192.0.2.128/25")
	samples := subnetSamples(p, opts)
	if !reflect.DeepEqual(samples, subnetSamples(p, opts)) {
		t.Fatal("sampling is not stable across restart")
	}
	seen := map[string]bool{}
	for _, host := range samples {
		if seen[host] || !p.Contains(netip.MustParseAddr(host)) {
			t.Fatalf("duplicate/out-of-scope sample %s", host)
		}
		seen[host] = true
	}
	for _, cidr := range []string{"::/0", "bad", "0.0.0.0/0"} {
		if _, err := DiscoverSubnets([]string{cidr}, nil); err == nil {
			t.Fatalf("accepted unsupported or unbounded range %s", cidr)
		}
	}
	if got := len(subnetSamples(netip.MustParsePrefix("192.0.2.0/24"), opts)); got != 5 {
		t.Fatalf("want 5 samples, got %d", got)
	}
}

func TestSubnetFirstHitEvidenceAndGlobalBudget(t *testing.T) {
	opts := DefaultSubnetDiscoveryOptions()
	opts.TCP, _ = normalizeHostDiscoveryOptions(&HostDiscoveryOptions{Ports: []int{80, 443}, Concurrency: 3, Timeout: 10 * time.Millisecond})
	prefixes, _ := subnetPrefixes(context.Background(), []string{"192.0.2.0/23"}, 10)
	var active, peak atomic.Int32
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if address == "192.0.2.1:80" {
			a, b := net.Pipe()
			b.Close()
			return a, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	events := 0
	opts.OnResult = func(SubnetDiscoveryResult) { events++ }
	results, err := discoverSubnets(context.Background(), prefixes, opts, dial)
	if err != nil || results[0].Status != HostConfirmed || results[0].EvidenceHost != "192.0.2.1" || results[0].Port != 80 || results[0].ProbedHosts != 1 || results[1].Status != HostUnconfirmed || results[1].ProbedHosts != 5 || events != 2 || peak.Load() > 3 || active.Load() != 0 {
		t.Fatalf("bad result/budget: %+v %v peak=%d active=%d", results, err, peak.Load(), active.Load())
	}
}

func TestSubnetCancellationJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := DefaultSubnetDiscoveryOptions()
	opts.TCP, _ = normalizeHostDiscoveryOptions(&HostDiscoveryOptions{Concurrency: 2, Timeout: time.Minute})
	prefixes, _ := subnetPrefixes(ctx, []string{"192.0.2.0/23"}, 10)
	var active, started atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		active.Add(1)
		defer active.Add(-1)
		if started.Add(1) == 2 {
			cancel()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	results, err := discoverSubnets(ctx, prefixes, opts, dial)
	if !errors.Is(err, context.Canceled) || active.Load() != 0 {
		t.Fatalf("workers not joined: %v %d", err, active.Load())
	}
	for _, r := range results {
		if r.Status != HostCanceled {
			t.Fatalf("cancelled work reported complete: %+v", r)
		}
	}
}

func TestSubnetAdditionalProbeAndProxyValidation(t *testing.T) {
	opts := DefaultSubnetDiscoveryOptions()
	opts.TCP.Concurrency = 1
	opts.AdditionalProbe = func(_ context.Context, host string) bool { return host == "192.0.2.1" }
	results, err := DiscoverSubnets([]string{"192.0.2.0/24"}, &opts)
	if err != nil || results[0].Source != "additional" || results[0].Status != HostConfirmed {
		t.Fatalf("additional probe ignored: %+v %v", results, err)
	}
	opts.TCP.ProxyURL = "socks5://127.0.0.1:1"
	if _, err := DiscoverSubnets([]string{"192.0.2.0/24"}, &opts); err == nil {
		t.Fatal("proxy allowed local additional probe")
	}
	for _, n := range []int{0, 255, -1} {
		bad := DefaultSubnetDiscoveryOptions()
		bad.HostSuffixes = []int{n}
		if _, err := DiscoverSubnets(nil, &bad); err == nil {
			t.Fatalf("accepted suffix %d", n)
		}
	}
}
