package gonmap

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// DefaultTCPHostDiscoveryPorts returns a fresh copy of the heuristic TCP ports.
func DefaultTCPHostDiscoveryPorts() []int { return []int{80, 443, 22, 3389, 445} }

type HostDiscoveryStatus string

const (
	HostConfirmed   HostDiscoveryStatus = "confirmed"
	HostUnconfirmed HostDiscoveryStatus = "unconfirmed"
	HostCanceled    HostDiscoveryStatus = "canceled"
	HostProbeError  HostDiscoveryStatus = "error"
)

type HostDiscoveryResult struct {
	Host   string
	Status HostDiscoveryStatus
	// Port is the first successful TCP connection, not a service fingerprint.
	Port  int
	Error string
}

type HostDiscoveryOptions struct {
	// Empty Ports uses 80,443,22,3389,445. Explicit ports must be in 1..65535.
	Ports []int
	// Timeout covers one connection including DNS and the SOCKS5 handshake.
	// Zero uses one second. Concurrency is the global connection limit (256).
	Timeout     time.Duration
	Concurrency int
	// PortsPerHost bounds concurrent probes per host; zero uses five.
	PortsPerHost int
	// ProxyURL supports socks5:// and socks5h://; there is no direct fallback.
	ProxyURL string
	// OnResult is called serially for finished hosts, in completion order.
	// It must return promptly. Unstarted hosts canceled by ctx have no callback.
	OnResult func(HostDiscoveryResult) `json:"-"`
}

type tcpDialContext func(context.Context, string, string) (net.Conn, error)

func normalizeHostDiscoveryOptions(options *HostDiscoveryOptions) (HostDiscoveryOptions, error) {
	opts := HostDiscoveryOptions{}
	if options != nil {
		opts = *options
	}
	if opts.Timeout < 0 || opts.Concurrency < 0 || opts.PortsPerHost < 0 {
		return opts, fmt.Errorf("host discovery timeout and concurrency must not be negative")
	}
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 256
	}
	if opts.PortsPerHost == 0 {
		opts.PortsPerHost = 5
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultTCPHostDiscoveryPorts()
	}
	opts.Ports = make([]int, 0, len(ports))
	seen := make(map[int]bool, len(ports))
	for _, port := range ports {
		if !isValidPort(port) {
			return opts, fmt.Errorf("invalid host discovery port: %d", port)
		}
		if !seen[port] {
			seen[port] = true
			opts.Ports = append(opts.Ports, port)
		}
	}
	return opts, nil
}

// newTCPDiscoveryDialer also serves ordinary TCP port discovery so both phases
// use the same transport. A timeout applies to the entire proxy handshake.
func newTCPDiscoveryDialer(proxyURL string, timeout time.Duration) (tcpDialContext, error) {
	direct := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	var dial tcpDialContext = direct.DialContext
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Hostname() == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("proxy must be a SOCKS5 URL with host and port")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || !isValidPort(port) {
			return nil, fmt.Errorf("invalid SOCKS5 proxy port")
		}
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, direct)
		if err != nil {
			return nil, err
		}
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("SOCKS5 dialer does not support cancellation")
		}
		dial = contextDialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return dial(probeCtx, network, address)
	}, nil
}

func DiscoverLiveHosts(hosts []string, options *HostDiscoveryOptions) ([]HostDiscoveryResult, error) {
	return DiscoverLiveHostsWithContext(context.Background(), hosts, options)
}

// DiscoverLiveHostsWithContext probes TCP connections only, without privileges
// or fingerprint traffic. Inputs are individual IPs/hostnames, not CIDRs.
// Results preserve first-seen input order after trimming/deduplication. A host
// with no successful connection is unconfirmed, NOT known to be offline.
// On cancellation all workers exit before returning partial results and ctx.Err().
func DiscoverLiveHostsWithContext(ctx context.Context, hosts []string, options *HostDiscoveryOptions) ([]HostDiscoveryResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts, err := normalizeHostDiscoveryOptions(options)
	if err != nil {
		return nil, err
	}
	dial, err := newTCPDiscoveryDialer(opts.ProxyURL, opts.Timeout)
	if err != nil {
		return nil, err
	}
	return discoverLiveHosts(ctx, hosts, opts, dial)
}

func discoverLiveHosts(ctx context.Context, hosts []string, opts HostDiscoveryOptions, dial tcpDialContext) ([]HostDiscoveryResult, error) {
	results := make([]HostDiscoveryResult, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" && !seen[host] {
			seen[host] = true
			results = append(results, HostDiscoveryResult{Host: host, Status: HostCanceled})
		}
	}
	if len(results) == 0 {
		return results, ctx.Err()
	}
	workers := min(opts.Concurrency, len(results))
	// This semaphore counts connections across ALL hosts, not per host.
	connections := make(chan struct{}, opts.Concurrency)
	jobs := make(chan int)
	finished := make(chan int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = probeLiveHost(ctx, results[index].Host, opts, dial, connections)
				finished <- index
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range results {
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
	if err := ctx.Err(); err != nil {
		for i := range results {
			if results[i].Status == HostCanceled {
				results[i].Error = err.Error()
			}
		}
		return results, err
	}
	return results, nil
}

func probeLiveHost(ctx context.Context, host string, opts HostDiscoveryOptions, dial tcpDialContext, connections chan struct{}) HostDiscoveryResult {
	hostCtx, stop := context.WithCancel(ctx)
	defer stop()
	result := HostDiscoveryResult{Host: host, Status: HostUnconfirmed}
	portJobs := make(chan int)
	var wg sync.WaitGroup
	var first sync.Once
	for i := 0; i < min(opts.PortsPerHost, min(len(opts.Ports), opts.Concurrency)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portJobs {
				select {
				case connections <- struct{}{}:
				case <-hostCtx.Done():
					return
				}
				if hostCtx.Err() != nil {
					<-connections
					return
				}
				probeCtx, cancel := context.WithTimeout(hostCtx, opts.Timeout)
				conn, err := dial(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err == nil && conn != nil && probeCtx.Err() == nil {
					first.Do(func() {
						result.Status, result.Port = HostConfirmed, port
						stop()
					})
				}
				if conn != nil {
					_ = conn.Close()
				}
				cancel()
				<-connections
			}
		}()
	}
sendPorts:
	for _, port := range opts.Ports {
		if hostCtx.Err() != nil {
			break
		}
		select {
		case portJobs <- port:
		case <-hostCtx.Done():
			break sendPorts
		}
	}
	close(portJobs)
	wg.Wait()
	if ctx.Err() != nil && result.Status != HostConfirmed {
		result.Status, result.Error = HostCanceled, ctx.Err().Error()
	}
	return result
}
