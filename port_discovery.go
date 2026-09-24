package gonmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	defaultDiscoveryTimeout     = time.Second
	defaultDiscoveryConcurrency = 1024
	defaultSYNDiscoveryRate     = 1500
)

type PortDiscoveryMode string

const (
	PortDiscoveryModeConnect PortDiscoveryMode = "connect"
	PortDiscoveryModeSYN     PortDiscoveryMode = "syn"
)

type PortDiscoveryOptions struct {
	Timeout     time.Duration
	Concurrency int
	Mode        PortDiscoveryMode
	Rate        int
}

type OpenPort struct {
	Host string
	Port int
}

func normalizePortDiscoveryOptions(options *PortDiscoveryOptions) PortDiscoveryOptions {
	normalized := PortDiscoveryOptions{
		Timeout:     defaultDiscoveryTimeout,
		Concurrency: defaultDiscoveryConcurrency,
	}
	if options == nil {
		return normalized
	}
	if options.Timeout > 0 {
		normalized.Timeout = options.Timeout
	}
	if options.Concurrency > 0 {
		normalized.Concurrency = options.Concurrency
	}
	if options.Mode != "" {
		normalized.Mode = options.Mode
	}
	if options.Rate > 0 {
		normalized.Rate = options.Rate
	}
	if normalized.Mode == "" {
		normalized.Mode = PortDiscoveryModeConnect
	}
	if normalized.Rate <= 0 {
		if normalized.Mode == PortDiscoveryModeSYN {
			normalized.Rate = defaultSYNDiscoveryRate
		} else {
			normalized.Rate = normalized.Concurrency
		}
	}
	return normalized
}

func ExpandPortRange(startPort, endPort int) []int {
	if startPort < 1 {
		startPort = 1
	}
	if endPort > 65535 {
		endPort = 65535
	}
	if startPort > endPort {
		return nil
	}

	ports := make([]int, 0, endPort-startPort+1)
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}
	return ports
}

func DiscoverOpenPorts(hosts []string, ports []int, options *PortDiscoveryOptions) []OpenPort {
	return DiscoverOpenPortsWithContext(context.Background(), hosts, ports, options)
}

func DiscoverOpenPortsWithContext(ctx context.Context, hosts []string, ports []int, options *PortDiscoveryOptions) []OpenPort {
	return DiscoverOpenPortsWithContextCallback(ctx, hosts, ports, options, nil)
}

// DiscoverOpenPortsWithContextCallback reports each open port as it is found.
// The callback runs serially; a slow callback delays Connect discovery.
func DiscoverOpenPortsWithContextCallback(ctx context.Context, hosts []string, ports []int, options *PortDiscoveryOptions, onOpen func(OpenPort)) []OpenPort {
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	opts := normalizePortDiscoveryOptions(options)
	if opts.Mode == PortDiscoveryModeSYN {
		openPorts, err := discoverOpenPortsSYNWithCallback(ctx, hosts, ports, opts, onOpen)
		if err == nil {
			return openPorts
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		fmt.Fprintf(os.Stderr, "syn discovery failed: %v\n", err)
		return nil
	}
	return discoverOpenPortsConnectWithCallback(ctx, hosts, ports, opts, onOpen)
}

func discoverOpenPortsConnect(ctx context.Context, hosts []string, ports []int, opts PortDiscoveryOptions) []OpenPort {
	return discoverOpenPortsConnectWithCallback(ctx, hosts, ports, opts, nil)
}

func discoverOpenPortsConnectWithCallback(ctx context.Context, hosts []string, ports []int, opts PortDiscoveryOptions, onOpen func(OpenPort)) []OpenPort {
	type job struct {
		host string
		port int
	}
	if ctx == nil {
		ctx = context.Background()
	}

	jobs := make(chan job, opts.Concurrency)
	results := make(chan OpenPort, opts.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{
				Timeout:   opts.Timeout,
				KeepAlive: -1,
			}
			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-jobs:
					if !ok {
						return
					}
					if ctx.Err() != nil {
						return
					}
					if !isValidPort(item.port) {
						continue
					}
					if isTCPOpen(ctx, dialer, item.host, item.port) {
						select {
						case results <- OpenPort{
							Host: item.host,
							Port: item.port,
						}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			if ctx.Err() != nil {
				return
			}
			if host == "" {
				continue
			}
			for _, port := range ports {
				select {
				case jobs <- job{host: host, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	openPorts := make([]OpenPort, 0, 16)
	for result := range results {
		openPorts = append(openPorts, result)
		if onOpen != nil {
			onOpen(result)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Host != openPorts[j].Host {
			return openPorts[i].Host < openPorts[j].Host
		}
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts
}

func isTCPOpen(ctx context.Context, dialer *net.Dialer, host string, port int) bool {
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}
