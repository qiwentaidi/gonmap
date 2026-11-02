package gonmap

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"sync"
)

// SubnetDiscoveryOptions controls IPv4 /24 sampling. A hit means at least one
// sampled host responded, never that every address in the subnet is alive.
type SubnetDiscoveryOptions struct {
	TCP HostDiscoveryOptions
	// Nil uses .1, .2, .254. An empty slice disables fixed samples.
	HostSuffixes []int
	// Additional deterministic pseudo-random samples per subnet, 0..254.
	// A nil options argument uses two; an explicit zero disables random samples.
	RandomSamples int
	// MaxSubnets bounds memory before network activity; zero uses 131072.
	MaxSubnets int
	// AdditionalProbe can confirm a host (e.g. ICMP) before TCP. It must
	// honor ctx and return only after its work exits. Disallowed with a proxy.
	AdditionalProbe func(context.Context, string) bool `json:"-"`
	// Called serially on completion. Must return promptly.
	OnResult func(SubnetDiscoveryResult) `json:"-"`
}

type SubnetDiscoveryResult struct {
	CIDR         string              `json:"cidr"`
	Status       HostDiscoveryStatus `json:"status"`
	EvidenceHost string              `json:"evidenceHost,omitempty"`
	Port         int                 `json:"port,omitempty"`
	Source       string              `json:"source,omitempty"`
	ProbedHosts  int                 `json:"probedHosts"`
}

func DefaultSubnetDiscoveryOptions() SubnetDiscoveryOptions {
	return SubnetDiscoveryOptions{HostSuffixes: []int{1, 2, 254}, RandomSamples: 2}
}

func DiscoverSubnets(cidrs []string, options *SubnetDiscoveryOptions) ([]SubnetDiscoveryResult, error) {
	return DiscoverSubnetsWithContext(context.Background(), cidrs, options)
}

// DiscoverSubnetsWithContext samples only addresses inside explicitly supplied
// IPv4 CIDRs. Overlapping CIDRs are deduplicated; narrower prefixes remain
// bounded to their original range. No-response results are unconfirmed.
// Cancellation joins all probes before returning partial results and ctx.Err().
func DiscoverSubnetsWithContext(ctx context.Context, cidrs []string, options *SubnetDiscoveryOptions) ([]SubnetDiscoveryResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts := DefaultSubnetDiscoveryOptions()
	if options != nil {
		opts = *options
	}
	var err error
	opts.TCP, err = normalizeHostDiscoveryOptions(&opts.TCP)
	if err != nil {
		return nil, err
	}
	if opts.TCP.ProxyURL != "" && opts.AdditionalProbe != nil {
		return nil, fmt.Errorf("additional subnet probes cannot bypass the TCP proxy")
	}
	if opts.HostSuffixes == nil {
		opts.HostSuffixes = []int{1, 2, 254}
	}
	if opts.RandomSamples < 0 || opts.RandomSamples > 254 {
		return nil, fmt.Errorf("random samples must be in 0..254")
	}
	for _, n := range opts.HostSuffixes {
		if n < 1 || n > 254 {
			return nil, fmt.Errorf("host suffix must be in 1..254: %d", n)
		}
	}
	if len(opts.HostSuffixes) == 0 && opts.RandomSamples == 0 {
		return nil, fmt.Errorf("at least one subnet sample is required")
	}
	if opts.MaxSubnets == 0 {
		opts.MaxSubnets = 131072
	}
	if opts.MaxSubnets < 1 {
		return nil, fmt.Errorf("max subnets must be positive")
	}
	prefixes, err := subnetPrefixes(ctx, cidrs, opts.MaxSubnets)
	if err != nil {
		return nil, err
	}
	dial, err := newTCPDiscoveryDialer(opts.TCP.ProxyURL, opts.TCP.Timeout)
	if err != nil {
		return nil, err
	}
	return discoverSubnets(ctx, prefixes, opts, dial)
}

func subnetPrefixes(ctx context.Context, cidrs []string, limit int) ([]netip.Prefix, error) {
	inputs := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("subnet discovery requires IPv4 CIDRs: %q", cidr)
		}
		inputs = append(inputs, p.Masked())
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Addr() == inputs[j].Addr() {
			return inputs[i].Bits() < inputs[j].Bits()
		}
		return inputs[i].Addr().Less(inputs[j].Addr())
	})
	var out []netip.Prefix
	var previous netip.Prefix
	for _, p := range inputs {
		if previous.IsValid() && previous.Bits() <= p.Bits() && previous.Contains(p.Addr()) {
			continue
		}
		previous = p
		n := 1
		if p.Bits() < 24 {
			n = 1 << (24 - p.Bits())
		}
		if n > limit-len(out) {
			return nil, fmt.Errorf("subnet discovery exceeds limit of %d subnets", limit)
		}
		start := p.Addr().As4()
		base := binary.BigEndian.Uint32(start[:])
		for i := 0; i < n; i++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var ip [4]byte
			binary.BigEndian.PutUint32(ip[:], base+uint32(i)*256)
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(ip), max(24, p.Bits())))
		}
	}
	return out, nil
}

func subnetSamples(p netip.Prefix, opts SubnetDiscoveryOptions) []string {
	base := p.Addr().As4()
	var out []string
	seen := make(map[int]bool)
	add := func(n int) bool {
		ip := base
		ip[3] = byte(n)
		addr := netip.AddrFrom4(ip)
		if seen[n] || !p.Contains(addr) {
			return false
		}
		seen[n] = true
		out = append(out, addr.String())
		return true
	}
	for _, n := range opts.HostSuffixes {
		add(n)
	}
	// Stable sampling permits safe checkpoint/restart without retaining PRNG state.
	rng := rand.New(rand.NewSource(int64(binary.BigEndian.Uint32(base[:])) + int64(p.Bits())))
	added := 0
	for _, n := range rng.Perm(254) {
		if added >= opts.RandomSamples {
			break
		}
		if add(n + 1) {
			added++
		}
	}
	// /31 and /32 endpoints are valid hosts; never invent out-of-range samples.
	if p.Bits() >= 31 && len(out) == 0 {
		out = append(out, p.Addr().String())
	}
	return out
}

func discoverSubnets(ctx context.Context, prefixes []netip.Prefix, opts SubnetDiscoveryOptions, dial tcpDialContext) ([]SubnetDiscoveryResult, error) {
	results := make([]SubnetDiscoveryResult, len(prefixes))
	for i, p := range prefixes {
		results[i] = SubnetDiscoveryResult{CIDR: p.String(), Status: HostCanceled}
	}
	workers := min(len(prefixes), opts.TCP.Concurrency)
	connections := make(chan struct{}, opts.TCP.Concurrency)
	jobs := make(chan int)
	finished := make(chan int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				r := &results[index]
				r.Status = HostUnconfirmed
				for _, host := range subnetSamples(prefixes[index], opts) {
					if ctx.Err() != nil {
						break
					}
					r.ProbedHosts++
					probeCtx, cancel := context.WithTimeout(ctx, opts.TCP.Timeout)
					alive := opts.AdditionalProbe != nil && opts.AdditionalProbe(probeCtx, host)
					cancel()
					if alive && ctx.Err() == nil {
						r.Status, r.EvidenceHost, r.Source = HostConfirmed, host, "additional"
						break
					}
					probe := probeLiveHost(ctx, host, opts.TCP, dial, connections)
					if probe.Status == HostConfirmed {
						r.Status, r.EvidenceHost, r.Port, r.Source = HostConfirmed, host, probe.Port, "tcp"
						break
					}
				}
				if ctx.Err() != nil && r.Status != HostConfirmed {
					r.Status = HostCanceled
				}
				finished <- index
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range prefixes {
			if ctx.Err() != nil {
				return
			}
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(finished) }()
	for index := range finished {
		if opts.OnResult != nil {
			opts.OnResult(results[index])
		}
	}
	return results, ctx.Err()
}
