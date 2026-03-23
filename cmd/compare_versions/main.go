package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHost       = "114.132.250.138"
	defaultWorkers    = 1000
	defaultTCPTimeout = 3 * time.Second
	defaultUDPTimeout = 5 * time.Second
	fullPortStart     = 1
	fullPortEnd       = 65535
)

const defaultPortGroupSpec = "21,22,23,25,53,U:53,U:69,80,81,U:88,110,111,U:111,123,U:123,135,U:137,139,U:161,U:177,389,U:427,443,445,465,500,515,U:520,U:523,548,623,U:626,636,873,902,1080,1099,1433,U:1434,1521,U:1604,U:1645,U:1701,1883,U:1900,2049,2181,2375,2379,U:2425,3128,3306,3389,4730,U:5060,5222,U:5351,U:5353,5432,5555,5601,5672,U:5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,U:11211,27017,U:33848,37777,50000,50070,61616"

type target struct {
	Label    string `json:"label"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Timeout  string `json:"timeout"`
}

type portResult struct {
	Label   string `json:"label"`
	Status  string `json:"status"`
	Service string `json:"service"`
}

type report struct {
	Name       string       `json:"name"`
	ElapsedMs  float64      `json:"elapsed_ms"`
	PeakHeap   uint64       `json:"peak_heap"`
	TotalAlloc uint64       `json:"total_alloc"`
	NumGC      uint32       `json:"gc_runs"`
	Discovered int          `json:"discovered"`
	Identified int          `json:"identified"`
	Total      int          `json:"total"`
	Results    []portResult `json:"results"`
}

type benchmark struct {
	Report report
	RSS    uint64
}

func main() {
	host := flag.String("host", defaultHost, "target host")
	workers := flag.Int("workers", defaultWorkers, "worker count")
	portSpec := flag.String("ports", defaultPortGroupSpec, "port group spec")
	fullTCP := flag.Bool("full-tcp", false, "scan all TCP ports")
	includeUDP := flag.Bool("include-udp", false, "include UDP entries from --ports")
	showAll := flag.Bool("show-all", false, "show all rows")
	flag.Parse()

	repoRoot, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	targets, err := buildTargets(*portSpec, *fullTCP, *includeUDP)
	if err != nil {
		panic(err)
	}

	current, err := runBenchmark(repoRoot, *host, *workers, targets)
	if err != nil {
		panic(err)
	}

	printSummary(*host, *workers, *showAll, current)
}

func runBenchmark(modulePath, host string, workers int, targets []target) (*benchmark, error) {
	runnerDir := filepath.Join(modulePath, ".compare_versions_runner")
	if err := os.MkdirAll(runnerDir, 0o755); err != nil {
		return nil, err
	}
	defer os.RemoveAll(runnerDir)

	if err := os.WriteFile(filepath.Join(runnerDir, "main.go"), []byte(buildRunnerSource()), 0o644); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(targets)
	if err != nil {
		return nil, err
	}
	targetsFile := filepath.Join(runnerDir, "targets.json")
	if err := os.WriteFile(targetsFile, payload, 0o644); err != nil {
		return nil, err
	}

	args := []string{"-l", "go", "run", ".", "--host", host, "--workers", strconv.Itoa(workers), "--targets-file", targetsFile}
	cmd := exec.Command("/usr/bin/time", args...)
	cmd.Dir = runnerDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("benchmark failed: %w\nstderr:\n%s", err, stderr.String())
	}

	var rpt report
	if err := json.Unmarshal(stdout.Bytes(), &rpt); err != nil {
		return nil, fmt.Errorf("parse report failed: %w\nstdout:\n%s", err, stdout.String())
	}

	_, rss := parseTimeOutput(stderr.String())
	return &benchmark{Report: rpt, RSS: rss}, nil
}

func printSummary(host string, workers int, showAll bool, current *benchmark) {
	fmt.Printf("Target: %s\n", host)
	fmt.Printf("Ports: %d\n", current.Report.Total)
	fmt.Printf("Workers: %d\n\n", workers)

	fmt.Println("Definitions:")
	fmt.Println("- discovered: port not classified as closed")
	fmt.Println("- identified: discovered port with service fingerprint")
	fmt.Println("- rss: maximum resident set size from /usr/bin/time")
	fmt.Println("- heap metrics: in-process Go heap stats")
	fmt.Println()

	fmt.Println("Current:")
	fmt.Printf("  elapsed: %.2fs\n", current.Report.ElapsedMs/1000.0)
	fmt.Printf("  rss: %s\n", humanBytes(current.RSS))
	fmt.Printf("  peak_heap: %s\n", humanBytes(current.Report.PeakHeap))
	fmt.Printf("  total_alloc: %s\n", humanBytes(current.Report.TotalAlloc))
	fmt.Printf("  gc_runs: %d\n", current.Report.NumGC)
	fmt.Printf("  discovered: %d/%d\n", current.Report.Discovered, current.Report.Total)
	fmt.Printf("  identified: %d/%d (%.2f%% of discovered)\n", current.Report.Identified, current.Report.Discovered, ratio(current.Report.Identified, current.Report.Discovered))
	fmt.Println()

	fmt.Println("Per-port summary:")
	fmt.Println("  note: default output hides closed/no-service noise; use --show-all to print every port")
	hidden := 0
	for _, item := range current.Report.Results {
		if !showAll && item.Status == "Closed" && item.Service == "" {
			hidden++
			continue
		}
		if !showAll && item.Status == "Open" && item.Service == "" {
			hidden++
			continue
		}
		if !showAll && item.Status == "Unknown" && item.Service == "" {
			hidden++
			continue
		}
		fmt.Printf("  %-8s %-10s %s\n", item.Label, item.Status, blank(item.Service))
	}
	if !showAll && hidden > 0 {
		fmt.Printf("  hidden rows: %d\n", hidden)
	}
}

func buildTargets(spec string, fullTCP, includeUDP bool) ([]target, error) {
	seen := map[string]struct{}{}
	var targets []target

	if fullTCP {
		for port := fullPortStart; port <= fullPortEnd; port++ {
			label := strconv.Itoa(port)
			targets = append(targets, target{
				Label:    label,
				Port:     port,
				Protocol: "tcp",
				Timeout:  defaultTCPTimeout.String(),
			})
			seen[label] = struct{}{}
		}
	}

	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		protocol := "tcp"
		timeout := defaultTCPTimeout
		label := raw
		portText := raw
		if strings.HasPrefix(strings.ToUpper(raw), "U:") {
			if !includeUDP {
				continue
			}
			protocol = "udp"
			timeout = defaultUDPTimeout
			portText = raw[2:]
			label = "U:" + portText
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port entry: %s", raw)
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		targets = append(targets, target{
			Label:    label,
			Port:     port,
			Protocol: protocol,
			Timeout:  timeout.String(),
		})
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Port == targets[j].Port {
			return targets[i].Protocol < targets[j].Protocol
		}
		return targets[i].Port < targets[j].Port
	})
	return targets, nil
}

func buildRunnerSource() string {
	return `package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qiwentaidi/gonmap"
)

type target struct {
	Label    string ` + "`json:\"label\"`" + `
	Port     int    ` + "`json:\"port\"`" + `
	Protocol string ` + "`json:\"protocol\"`" + `
	Timeout  string ` + "`json:\"timeout\"`" + `
}

type portResult struct {
	Label   string ` + "`json:\"label\"`" + `
	Status  string ` + "`json:\"status\"`" + `
	Service string ` + "`json:\"service\"`" + `
}

type report struct {
	Name       string       ` + "`json:\"name\"`" + `
	ElapsedMs  float64      ` + "`json:\"elapsed_ms\"`" + `
	PeakHeap   uint64       ` + "`json:\"peak_heap\"`" + `
	TotalAlloc uint64       ` + "`json:\"total_alloc\"`" + `
	NumGC      uint32       ` + "`json:\"gc_runs\"`" + `
	Discovered int          ` + "`json:\"discovered\"`" + `
	Identified int          ` + "`json:\"identified\"`" + `
	Total      int          ` + "`json:\"total\"`" + `
	Results    []portResult ` + "`json:\"results\"`" + `
}

func main() {
	host := flag.String("host", "", "target host")
	workers := flag.Int("workers", 1000, "worker count")
	targetsFile := flag.String("targets-file", "", "targets payload file")
	flag.Parse()

	targetPayload, err := os.ReadFile(*targetsFile)
	if err != nil {
		panic(err)
	}
	var targets []target
	if err := json.Unmarshal(targetPayload, &targets); err != nil {
		panic(err)
	}

	results := make([]portResult, len(targets))
	jobs := make(chan int, len(targets))

	var peakHeap uint64
	var stop atomic.Bool
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if stop.Load() {
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

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			engine := gonmap.New()
			for idx := range jobs {
				target := targets[idx]
				timeout, err := time.ParseDuration(target.Timeout)
				if err != nil {
					panic(err)
				}
				protocol := gonmap.ScanProtocolTCP
				if target.Protocol == "udp" {
					protocol = gonmap.ScanProtocolUDP
				}
				status, response := engine.ScanWithOptions(*host, target.Port, &gonmap.ScanOptions{
					Timeout:  timeout,
					Protocol: protocol,
				})
				service := ""
				if response != nil && response.FingerPrint != nil {
					service = response.FingerPrint.Service
				}
				results[idx] = portResult{Label: target.Label, Status: status.String(), Service: service}
			}
		}()
	}

	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	stop.Store(true)
	sampler.Wait()
	elapsed := time.Since(start)

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	discovered := 0
	identified := 0
	for _, item := range results {
		if item.Status != "Closed" {
			discovered++
		}
		if item.Status == "Matched" && item.Service != "" {
			identified++
		}
	}

	reportPayload, err := json.Marshal(report{
		Name:       "current",
		ElapsedMs:  float64(elapsed.Microseconds()) / 1000.0,
		PeakHeap:   peakHeap,
		TotalAlloc: after.TotalAlloc - before.TotalAlloc,
		NumGC:      after.NumGC - before.NumGC,
		Discovered: discovered,
		Identified: identified,
		Total:      len(results),
		Results:    results,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(reportPayload))
}
`
}

func parseTimeOutput(output string) (float64, uint64) {
	var elapsedMs float64
	var rssBytes uint64
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, " real") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				elapsedMs = parseElapsed(fields[0])
			}
		}
		if strings.Contains(line, "maximum resident set size") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if rss, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					rssBytes = rss
				}
			}
		}
	}
	return elapsedMs, rssBytes
}

func parseElapsed(value string) float64 {
	value = strings.TrimSpace(strings.TrimSuffix(value, "s"))
	if strings.Contains(value, ":") {
		parts := strings.Split(value, ":")
		if len(parts) == 2 {
			minutes, _ := strconv.ParseFloat(parts[0], 64)
			seconds, _ := strconv.ParseFloat(parts[1], 64)
			return (minutes*60 + seconds) * 1000
		}
	}
	seconds, _ := strconv.ParseFloat(value, 64)
	return seconds * 1000
}

func blank(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
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
