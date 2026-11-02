package lib

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSubnetDiscoveryInheritsSDKProxy(t *testing.T) {
	proxyURL, requests := startHostDiscoveryProxy(t, func(host string, port int) bool { return host == "192.0.2.1" && port == 80 })
	sdk := New(&Options{ProxyURL: proxyURL})
	opts := DefaultSubnetDiscoveryOptions()
	opts.HostSuffixes = []int{1, 2}
	opts.RandomSamples = 0
	opts.TCP = HostDiscoveryOptions{Ports: []int{80}, Concurrency: 2, Timeout: time.Second}
	results, err := sdk.DiscoverSubnetsWithContext(context.Background(), []string{"192.0.2.0/23"}, &opts)
	if err != nil || len(results) != 2 || results[0].Status != HostConfirmed || results[0].EvidenceHost != "192.0.2.1" || results[1].Status != HostUnconfirmed {
		t.Fatalf("proxy results: %+v %v", results, err)
	}
	got := requests()
	if len(got) != 3 {
		t.Fatalf("first hit/remaining subnet not routed through proxy: %v", got)
	}
	for _, address := range got {
		if !strings.HasPrefix(address, "192.0.") {
			t.Fatalf("out-of-scope probe: %s", address)
		}
	}
	if opts.TCP.ProxyURL != "" {
		t.Fatal("SDK mutated caller options")
	}
}
