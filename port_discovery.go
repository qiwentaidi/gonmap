package gonmap

import (
	"net"
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
	Timeout            time.Duration
	Concurrency        int
	Mode               PortDiscoveryMode
	Rate               int
	DisableSYNFallback bool
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
	if options.DisableSYNFallback {
		normalized.DisableSYNFallback = true
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
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}

	opts := normalizePortDiscoveryOptions(options)
	if opts.Mode == PortDiscoveryModeSYN {
		openPorts, err := discoverOpenPortsSYN(hosts, ports, opts)
		if err == nil {
			return openPorts
		}
		if opts.DisableSYNFallback {
			return nil
		}
	}
	return discoverOpenPortsConnect(hosts, ports, opts)
}

func discoverOpenPortsConnect(hosts []string, ports []int, opts PortDiscoveryOptions) []OpenPort {
	type job struct {
		host string
		port int
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
			for item := range jobs {
				if !isValidPort(item.port) {
					continue
				}
				if isTCPOpen(dialer, item.host, item.port) {
					results <- OpenPort{
						Host: item.host,
						Port: item.port,
					}
				}
			}
		}()
	}

	go func() {
		for _, host := range hosts {
			if host == "" {
				continue
			}
			for _, port := range ports {
				jobs <- job{host: host, port: port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	openPorts := make([]OpenPort, 0, 16)
	for result := range results {
		openPorts = append(openPorts, result)
	}

	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Host != openPorts[j].Host {
			return openPorts[i].Host < openPorts[j].Host
		}
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts
}

func isTCPOpen(dialer *net.Dialer, host string, port int) bool {
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}
