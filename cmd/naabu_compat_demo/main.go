package main

import (
	"flag"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants"
	"github.com/qiwentaidi/gonmap"
)

const (
	defaultHost       = "114.132.250.138"
	defaultWorkers    = 1000
	defaultDiscover   = 4096
	tcpScanTimeout    = 8 * time.Second
	udpScanTimeout    = 5 * time.Second
	defaultPortGroups = "21,22,23,25,53,U:53,U:69,80,81,U:88,110,111,U:111,123,U:123,135,U:137,139,U:161,U:177,389,U:427,443,445,465,500,515,U:520,U:523,548,623,U:626,636,873,902,1080,1099,1433,U:1434,1521,U:1604,U:1645,U:1701,1883,U:1900,2049,2181,2375,2379,U:2425,3128,3306,3389,4730,U:5060,5222,U:5351,U:5353,5432,5555,5601,5672,U:5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,U:11211,27017,U:33848,37777,50000,50070,61616"
)

type address struct {
	Label    string
	Host     string
	Port     int
	Protocol string
	Timeout  time.Duration
}

type result struct {
	Label      string
	Host       string
	Port       int
	Status     gonmap.Status
	Protocol   string
	Raw        string
	HasService bool
}

func main() {
	host := flag.String("host", defaultHost, "target host")
	workers := flag.Int("workers", defaultWorkers, "ants pool size")
	discoveryWorkers := flag.Int("discover-workers", defaultDiscover, "tcp connect discovery concurrency")
	fullTCP := flag.Bool("full-tcp", false, "scan all TCP ports (1-65535)")
	includeUDP := flag.Bool("include-udp", false, "include UDP ports from default port groups")
	flag.Parse()

	addresses, err := buildAddresses(*host, defaultPortGroups, *fullTCP, *includeUDP)
	if err != nil {
		panic(err)
	}
	addresses = filterTCPByDiscovery(addresses, *host, *discoveryWorkers)

	start := time.Now()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var peakHeap uint64
	var stopSampler atomic.Bool
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if stopSampler.Load() {
				return
			}
			<-ticker.C
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			for {
				current := atomic.LoadUint64(&peakHeap)
				if ms.HeapAlloc <= current || atomic.CompareAndSwapUint64(&peakHeap, current, ms.HeapAlloc) {
					break
				}
			}
		}
	}()

	retChan := make(chan result, 1024)
	results := make([]result, 0, 256)
	var resultMutex sync.Mutex
	collectorDone := make(chan struct{})
	go func() {
		for item := range retChan {
			resultMutex.Lock()
			results = append(results, item)
			resultMutex.Unlock()
		}
		close(collectorDone)
	}()

	var wg sync.WaitGroup
	portScan := func(v interface{}) {
		defer wg.Done()
		add, ok := v.(address)
		if !ok {
			return
		}

		scanner := gonmap.New()
		status, response := scanner.Scan(add.Host, add.Port, add.Timeout, "")
		if status == gonmap.Closed || status == gonmap.Unknown {
			return
		}

		raw := ""
		scheme := "unknown"
		if response != nil && response.FingerPrint != nil && response.FingerPrint.Service != "" {
			scheme = response.FingerPrint.Service
			raw = response.Raw
		}
		if scheme == "unknown" {
			scheme = gonmap.GuessProtocol(add.Port)
		}

		retChan <- result{
			Label:      add.Label,
			Host:       add.Host,
			Port:       add.Port,
			Status:     status,
			Protocol:   scheme,
			Raw:        raw,
			HasService: scheme != "" && scheme != "unknown",
		}
	}

	threadPool, err := ants.NewPoolWithFunc(*workers, portScan)
	if err != nil {
		panic(err)
	}
	defer threadPool.Release()

	for _, add := range addresses {
		wg.Add(1)
		if invokeErr := threadPool.Invoke(add); invokeErr != nil {
			wg.Done()
		}
	}

	wg.Wait()
	close(retChan)
	<-collectorDone
	stopSampler.Store(true)
	samplerWG.Wait()

	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	fmt.Printf("Target: %s\n", *host)
	fmt.Printf("DiscoveryWorkers: %d\n", *discoveryWorkers)
	fmt.Printf("Workers: %d\n", *workers)
	fmt.Printf("Ports: %d\n", len(addresses))
	fmt.Printf("Elapsed: %s\n", elapsed)
	fmt.Printf("CurrentMemory: heap_alloc=%s heap_sys=%s peak_heap=%s\n",
		humanBytes(after.HeapAlloc),
		humanBytes(after.HeapSys),
		humanBytes(atomic.LoadUint64(&peakHeap)),
	)
	fmt.Printf("ScanDelta: heap_alloc=%s total_alloc=%s gc_runs=%d\n\n",
		humanBytes(deltaUint64(after.HeapAlloc, before.HeapAlloc)),
		humanBytes(after.TotalAlloc-before.TotalAlloc),
		after.NumGC-before.NumGC,
	)

	for _, item := range results {
		fmt.Printf("%-8s %-10s", item.Label, item.Status)
		if item.Protocol != "" && item.Protocol != "unknown" {
			fmt.Printf(" protocol=%s", item.Protocol)
		}
		fmt.Println()
	}
}

func filterTCPByDiscovery(addresses []address, host string, discoveryWorkers int) []address {
	tcpPorts := make([]int, 0, len(addresses))
	udpAddresses := make([]address, 0, len(addresses))
	addressByPort := make(map[int]address, len(addresses))
	for _, item := range addresses {
		if item.Protocol == "udp" {
			udpAddresses = append(udpAddresses, item)
			continue
		}
		tcpPorts = append(tcpPorts, item.Port)
		addressByPort[item.Port] = item
	}

	if len(tcpPorts) == 0 {
		return udpAddresses
	}

	openPorts := gonmap.DiscoverOpenPorts([]string{host}, tcpPorts, &gonmap.PortDiscoveryOptions{
		Timeout:     time.Second,
		Concurrency: discoveryWorkers,
	})

	filtered := make([]address, 0, len(openPorts)+len(udpAddresses))
	for _, openPort := range openPorts {
		if item, ok := addressByPort[openPort.Port]; ok {
			filtered = append(filtered, item)
		}
	}
	filtered = append(filtered, udpAddresses...)
	return filtered
}

func buildAddresses(host, spec string, fullTCP, includeUDP bool) ([]address, error) {
	if fullTCP {
		addresses := make([]address, 0, 65535)
		for port := 1; port <= 65535; port++ {
			addresses = append(addresses, address{
				Label:    strconv.Itoa(port),
				Host:     host,
				Port:     port,
				Protocol: "tcp",
				Timeout:  tcpScanTimeout,
			})
		}
		return addresses, nil
	}

	parts := strings.Split(spec, ",")
	addresses := make([]address, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		protocol := "tcp"
		timeout := tcpScanTimeout
		label := part
		portExpr := part
		if strings.HasPrefix(strings.ToUpper(part), "U:") {
			if !includeUDP {
				continue
			}
			protocol = "udp"
			timeout = udpScanTimeout
			portExpr = strings.TrimPrefix(part, "U:")
			label = "U:" + portExpr
		}

		port, err := strconv.Atoi(portExpr)
		if err != nil {
			return nil, fmt.Errorf("invalid port expression %q: %w", part, err)
		}

		addresses = append(addresses, address{
			Label:    label,
			Host:     host,
			Port:     port,
			Protocol: protocol,
			Timeout:  timeout,
		})
	}
	return addresses, nil
}

func humanBytes(size uint64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := uint64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func deltaUint64(after, before uint64) uint64 {
	if after >= before {
		return after - before
	}
	return 0
}
