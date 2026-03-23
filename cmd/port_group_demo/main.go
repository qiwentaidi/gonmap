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

	"github.com/qiwentaidi/gonmap/lib"
)

const (
	targetHost     = "114.132.250.138"
	workerCount    = 16
	tcpScanTimeout = 3 * time.Second
	udpScanTimeout = 5 * time.Second
)

const portGroupSpec = "21,22,23,25,53,U:53,U:69,80,81,U:88,110,111,U:111,123,U:123,135,U:137,139,U:161,U:177,389,U:427,443,445,465,500,515,U:520,U:523,548,623,U:626,636,873,902,1080,1099,1433,U:1434,1521,U:1604,U:1645,U:1701,1883,U:1900,2049,2181,2375,2379,U:2425,3128,3306,3389,4730,U:5060,5222,U:5351,U:5353,5432,5555,5601,5672,U:5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,U:11211,27017,U:33848,37777,50000,50070,61616"

type scanTarget struct {
	Label    string
	Port     int
	Protocol lib.ScanProtocol
	Timeout  time.Duration
}

type scanResult struct {
	Index    int
	Target   scanTarget
	Status   lib.Status
	Response *lib.Response
}

func main() {
	host := flag.String("host", targetHost, "target host")
	workers := flag.Int("workers", workerCount, "worker count")
	fullTCP := flag.Bool("full-tcp", false, "scan all TCP ports (1-65535)")
	flag.Parse()

	targets, err := buildTargets(portGroupSpec, *fullTCP)
	if err != nil {
		panic(err)
	}

	sdk := lib.New(nil)
	start := time.Now()

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	jobs := make(chan int, len(targets))
	results := make(chan scanResult, len(targets))

	var wg sync.WaitGroup
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

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				target := targets[idx]
				status, response := sdk.Scan(*host, target.Port, &lib.ScanOptions{
					Timeout:  target.Timeout,
					Protocol: target.Protocol,
				})
				results <- scanResult{
					Index:    idx,
					Target:   target,
					Status:   status,
					Response: response,
				}
			}
		}()
	}

	for i := range targets {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	stopSampler.Store(true)
	samplerWG.Wait()
	close(results)

	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	ordered := make([]scanResult, 0, len(targets))
	for result := range results {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Index < ordered[j].Index
	})

	fmt.Printf("Target: %s\n", *host)
	fmt.Printf("Workers: %d\n", *workers)
	fmt.Printf("Ports: %d\n", len(targets))
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

	for _, result := range ordered {
		if result.Status == lib.Closed || result.Status == lib.Unknown {
			continue
		}
		fmt.Printf("%-8s %-10s", result.Target.Label, result.Status)
		if result.Response == nil || result.Response.FingerPrint == nil {
			fmt.Println()
			continue
		}

		fingerprint := result.Response.FingerPrint
		if fingerprint.Service != "" {
			fmt.Printf(" service=%s", fingerprint.Service)
		}
		if fingerprint.ProductName != "" {
			fmt.Printf(" product=%s", fingerprint.ProductName)
		}
		if fingerprint.Version != "" {
			fmt.Printf(" version=%s", fingerprint.Version)
		}
		if fingerprint.Info != "" {
			fmt.Printf(" info=%s", fingerprint.Info)
		}
		fmt.Println()
	}
}

func buildTargets(spec string, fullTCP bool) ([]scanTarget, error) {
	if fullTCP {
		targets := make([]scanTarget, 0, 65535)
		for port := 1; port <= 65535; port++ {
			targets = append(targets, scanTarget{
				Label:    strconv.Itoa(port),
				Port:     port,
				Protocol: lib.ScanProtocolTCP,
				Timeout:  tcpScanTimeout,
			})
		}
		return targets, nil
	}
	return parsePortGroupSpec(spec)
}

func parsePortGroupSpec(spec string) ([]scanTarget, error) {
	parts := strings.Split(spec, ",")
	targets := make([]scanTarget, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		protocol := lib.ScanProtocolTCP
		timeout := tcpScanTimeout
		label := part
		portExpr := part
		if strings.HasPrefix(part, "U:") {
			protocol = lib.ScanProtocolUDP
			timeout = udpScanTimeout
			portExpr = strings.TrimPrefix(part, "U:")
		}

		var port int
		if _, err := fmt.Sscanf(portExpr, "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid port expression %q: %w", part, err)
		}

		targets = append(targets, scanTarget{
			Label:    label,
			Port:     port,
			Protocol: protocol,
			Timeout:  timeout,
		})
	}
	return targets, nil
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
