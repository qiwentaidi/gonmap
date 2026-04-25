package lib

import (
	"sort"
	"sync"
	"time"
)

const (
	defaultFingerprintWorkers        = 64
	defaultSuspiciousOpenThreshold   = 128
	defaultSuspiciousHighPortStart   = 10000
	defaultSuspiciousOpenRatio       = 0.60
)

type BatchScanOptions struct {
	DiscoveryOptions           PortDiscoveryOptions
	FingerprintOptions         ScanOptions
	FingerprintWorkers         int
	SuspiciousOpenThreshold    int
	SuspiciousHighPortStart    int
	SuspiciousOpenRatio        float64
}

type BatchPortResult struct {
	Port             int
	Status           Status
	Response         *Response
	Suspicious       bool
	SuspiciousReason string
	LikelyWrapped    bool
	WrappedReason    string
}

type HostBatchResult struct {
	Host             string
	OpenPorts        []int
	Results          []BatchPortResult
	StablePorts      []int
	SuspiciousPorts  []int
	LikelyWrappedPorts []int
	LikelyNoise      bool
	NoiseReason      string
}

type normalizedBatchScanOptions struct {
	discoveryOptions        PortDiscoveryOptions
	fingerprintOptions      ScanOptions
	fingerprintWorkers      int
	suspiciousOpenThreshold int
	suspiciousHighPortStart int
	suspiciousOpenRatio     float64
}

func normalizeBatchScanOptions(options *BatchScanOptions) normalizedBatchScanOptions {
	normalized := normalizedBatchScanOptions{
		discoveryOptions: PortDiscoveryOptions{
			Timeout:     time.Second,
			Concurrency: 1024,
		},
		fingerprintWorkers:      defaultFingerprintWorkers,
		suspiciousOpenThreshold: defaultSuspiciousOpenThreshold,
		suspiciousHighPortStart: defaultSuspiciousHighPortStart,
		suspiciousOpenRatio:     defaultSuspiciousOpenRatio,
	}
	if options == nil {
		return normalized
	}
	if options.DiscoveryOptions.Timeout > 0 {
		normalized.discoveryOptions.Timeout = options.DiscoveryOptions.Timeout
	}
	if options.DiscoveryOptions.Concurrency > 0 {
		normalized.discoveryOptions.Concurrency = options.DiscoveryOptions.Concurrency
	}
	normalized.fingerprintOptions = options.FingerprintOptions
	if options.FingerprintWorkers > 0 {
		normalized.fingerprintWorkers = options.FingerprintWorkers
	}
	if options.SuspiciousOpenThreshold > 0 {
		normalized.suspiciousOpenThreshold = options.SuspiciousOpenThreshold
	}
	if options.SuspiciousHighPortStart > 0 {
		normalized.suspiciousHighPortStart = options.SuspiciousHighPortStart
	}
	if options.SuspiciousOpenRatio > 0 {
		normalized.suspiciousOpenRatio = options.SuspiciousOpenRatio
	}
	return normalized
}

func (s *SDK) ScanHostPorts(host string, ports []int, options *BatchScanOptions) *HostBatchResult {
	results := s.ScanHostsPorts([]string{host}, ports, options)
	if len(results) == 0 {
		return &HostBatchResult{Host: host}
	}
	return &results[0]
}

func (s *SDK) ScanHostsPorts(hosts []string, ports []int, options *BatchScanOptions) []HostBatchResult {
	if len(hosts) == 0 {
		return nil
	}

	normalized := normalizeBatchScanOptions(options)
	openPorts := s.DiscoverOpenPorts(hosts, ports, &normalized.discoveryOptions)
	groupedOpen := make(map[string][]int, len(hosts))
	for _, item := range openPorts {
		groupedOpen[item.Host] = append(groupedOpen[item.Host], item.Port)
	}

	groupedResults := s.identifyOpenPorts(groupedOpen, normalized)

	hostResults := make([]HostBatchResult, 0, len(hosts))
	for _, host := range hosts {
		openForHost := append([]int(nil), groupedOpen[host]...)
		sort.Ints(openForHost)
		result := analyzeHostBatchResult(host, openForHost, groupedResults[host], normalized)
		hostResults = append(hostResults, result)
	}
	return hostResults
}

func AnalyzeHostResults(host string, openPorts []int, results []BatchPortResult, options *BatchScanOptions) HostBatchResult {
	normalized := normalizeBatchScanOptions(options)
	copyOpenPorts := append([]int(nil), openPorts...)
	sort.Ints(copyOpenPorts)

	copyResults := make([]BatchPortResult, len(results))
	copy(copyResults, results)
	sort.Slice(copyResults, func(i, j int) bool {
		return copyResults[i].Port < copyResults[j].Port
	})

	return analyzeHostBatchResult(host, copyOpenPorts, copyResults, normalized)
}

func (s *SDK) identifyOpenPorts(groupedOpen map[string][]int, options normalizedBatchScanOptions) map[string][]BatchPortResult {
	type job struct {
		host string
		port int
	}

	resultsByHost := make(map[string][]BatchPortResult, len(groupedOpen))
	var mu sync.Mutex
	jobs := make(chan job, options.fingerprintWorkers)

	var wg sync.WaitGroup
	for i := 0; i < options.fingerprintWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				status, response := s.Scan(item.host, item.port, &options.fingerprintOptions)
				mu.Lock()
				resultsByHost[item.host] = append(resultsByHost[item.host], BatchPortResult{
					Port:     item.port,
					Status:   status,
					Response: response,
				})
				mu.Unlock()
			}
		}()
	}

	for host, ports := range groupedOpen {
		for _, port := range ports {
			jobs <- job{host: host, port: port}
		}
	}
	close(jobs)
	wg.Wait()

	for host := range resultsByHost {
		sort.Slice(resultsByHost[host], func(i, j int) bool {
			return resultsByHost[host][i].Port < resultsByHost[host][j].Port
		})
	}

	return resultsByHost
}

func analyzeHostBatchResult(host string, openPorts []int, results []BatchPortResult, options normalizedBatchScanOptions) HostBatchResult {
	analyzed := make([]BatchPortResult, len(results))
	copy(analyzed, results)

	suspiciousCount := 0
	for index := range analyzed {
		reason := detectSuspiciousReason(analyzed[index], options)
		if reason == "" {
			wrappedReason := detectWrappedReason(analyzed[index], options)
			if wrappedReason == "" {
				continue
			}
			analyzed[index].LikelyWrapped = true
			analyzed[index].WrappedReason = wrappedReason
			suspiciousCount++
			continue
		}
		analyzed[index].Suspicious = true
		analyzed[index].SuspiciousReason = reason
		analyzed[index].LikelyWrapped = true
		analyzed[index].WrappedReason = "generic open behavior on high port"
		suspiciousCount++
	}

	output := HostBatchResult{
		Host:      host,
		OpenPorts: append([]int(nil), openPorts...),
		Results:   analyzed,
	}
	for _, item := range analyzed {
		if item.LikelyWrapped {
			output.LikelyWrappedPorts = append(output.LikelyWrappedPorts, item.Port)
		}
		if item.Suspicious || item.LikelyWrapped {
			output.SuspiciousPorts = append(output.SuspiciousPorts, item.Port)
			continue
		}
		output.StablePorts = append(output.StablePorts, item.Port)
	}

	if len(openPorts) >= options.suspiciousOpenThreshold && len(openPorts) > 0 {
		ratio := float64(suspiciousCount) / float64(len(openPorts))
		if ratio >= options.suspiciousOpenRatio {
			output.LikelyNoise = true
			output.NoiseReason = "high open-port volume with mostly generic or wrapped responses"
		}
	}

	return output
}

func detectSuspiciousReason(result BatchPortResult, options normalizedBatchScanOptions) string {
	if result.Port < options.suspiciousHighPortStart {
		return ""
	}
	if result.Status != Open {
		return ""
	}
	if result.Response != nil && result.Response.Raw != "" {
		return ""
	}
	return "generic open without fingerprint on high port"
}

func detectWrappedReason(result BatchPortResult, options normalizedBatchScanOptions) string {
	if result.Port < options.suspiciousHighPortStart {
		return ""
	}
	if result.Response == nil || result.Response.FingerPrint == nil {
		return ""
	}
	if result.Status != Matched {
		return ""
	}
	fingerprint := result.Response.FingerPrint
	if fingerprint.ProductName != "" || fingerprint.Version != "" || fingerprint.Info != "" {
		return ""
	}
	switch fingerprint.Service {
	case "http-proxy", "ssl":
		return "generic wrapped service fingerprint on high port"
	default:
		return ""
	}
}
