package lib

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// scanLiveHostsPorts keeps the admission phase separate from port/fingerprint
// work. In particular, an unconfirmed host never enters the full port queue.
func (s *SDK) scanLiveHostsPorts(ctx context.Context, hosts []string, ports []int, options *BatchScanOptions) []HostBatchResult {
	if ctx == nil {
		ctx = context.Background()
	}
	scanOptions := *options
	hostOptions := *options.HostDiscovery
	// A batch must use one network path for all three phases. Explicit overrides
	// must agree; never silently probe the local network for a proxied task.
	proxyURL := ""
	var configErr error
	for _, value := range []string{hostOptions.ProxyURL, scanOptions.DiscoveryOptions.ProxyURL, scanOptions.FingerprintOptions.ProxyURL} {
		if value == "" {
			continue
		}
		if proxyURL != "" && proxyURL != value {
			configErr = fmt.Errorf("host discovery, port discovery and fingerprint proxies must agree")
		}
		proxyURL = value
	}
	if proxyURL == "" {
		proxyURL = s.defaultScanOptions.ProxyURL
	}
	if proxyURL != "" && scanOptions.DiscoveryOptions.Mode == PortDiscoveryModeSYN {
		configErr = fmt.Errorf("SYN discovery cannot use a proxy")
	}
	protocol := scanOptions.FingerprintOptions.Protocol
	if protocol == "" {
		protocol = s.defaultScanOptions.Protocol
	}
	if protocol == ScanProtocolUDP {
		configErr = fmt.Errorf("TCP host discovery cannot filter a UDP batch")
	}
	if configErr != nil {
		return hostDiscoveryFailure(hosts, configErr)
	}
	hostOptions.ProxyURL = proxyURL
	scanOptions.DiscoveryOptions.ProxyURL = proxyURL
	scanOptions.FingerprintOptions.ProxyURL = proxyURL
	probes, err := s.DiscoverLiveHostsWithContext(ctx, hosts, &hostOptions)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return hostDiscoveryFailure(hosts, err)
	}
	results := make([]HostBatchResult, len(probes))
	liveHosts := make([]string, 0, len(probes))
	indices := make(map[string]int, len(probes))
	for i := range probes {
		results[i] = HostBatchResult{Host: probes[i].Host, HostDiscovery: &probes[i]}
		indices[probes[i].Host] = i
		if probes[i].Status == HostConfirmed {
			liveHosts = append(liveHosts, probes[i].Host)
		}
	}
	// Even confirmed hosts must not start scanning after a canceled preflight.
	if err != nil || ctx.Err() != nil || len(liveHosts) == 0 {
		return results
	}
	for _, scanned := range s.scanHostsPortsWithDiscovery(ctx, liveHosts, ports, &scanOptions, s.DiscoverOpenPortsWithContextCallback) {
		i := indices[scanned.Host]
		scanned.HostDiscovery = results[i].HostDiscovery
		results[i] = scanned
	}
	return results
}

func hostDiscoveryFailure(hosts []string, err error) []HostBatchResult {
	results := make([]HostBatchResult, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		results = append(results, HostBatchResult{Host: host, HostDiscovery: &HostDiscoveryResult{
			Host: host, Status: HostProbeError, Error: err.Error(),
		}})
	}
	return results
}
