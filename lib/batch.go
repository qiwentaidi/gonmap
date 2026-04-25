package lib

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultFingerprintWorkers        = 64
	defaultSuspiciousOpenThreshold   = 128
	defaultSuspiciousHighPortStart   = 10000
	defaultSuspiciousOpenRatio       = 0.60
	minRepeatedHTTPNoisePorts        = 3
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
	repeatedHTTPNoiseReasons := detectRepeatedHTTPNoiseReasons(analyzed, options)

	suspiciousCount := 0
	for index := range analyzed {
		reason := repeatedHTTPNoiseReasons[analyzed[index].Port]
		if reason == "" {
			reason = detectSuspiciousReason(analyzed[index], options)
		}
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
	if reason := detectGenericOpenReason(result); reason != "" {
		return reason
	}
	if reason := detectGenericHTTPReason(result); reason != "" {
		return reason
	}
	return ""
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

func detectGenericOpenReason(result BatchPortResult) string {
	if result.Status != Open && result.Status != NotMatched {
		return ""
	}
	if result.Response == nil {
		return "generic open without fingerprint on high port"
	}
	if result.Response.Raw != "" {
		return ""
	}
	if hasUsefulFingerprintMetadata(result.Response.FingerPrint) {
		return ""
	}
	return "generic open without fingerprint on high port"
}

func detectGenericHTTPReason(result BatchPortResult) string {
	if result.Status != Matched || result.Response == nil || result.Response.Raw == "" {
		return ""
	}
	fingerprint := result.Response.FingerPrint
	if fingerprint == nil {
		return ""
	}
	if hasStrongFingerprintMetadata(fingerprint) {
		return ""
	}
	if fingerprint.ProductName != "" && !isGenericHTTPProduct(fingerprint.ProductName) {
		return ""
	}
	switch fingerprint.Service {
	case "http", "ssl/http", "http-proxy":
	default:
		return ""
	}

	raw := strings.ToLower(result.Response.Raw)
	if !strings.Contains(raw, "server: tengine") {
		return ""
	}
	if extractHTTPStatusCode(raw) == 410 {
		return ""
	}
	for _, marker := range []string{
		" 400 ",
		" 401 ",
		" 403 ",
		" 404 ",
		" 405 ",
		" 408 ",
		" 410 ",
		" 421 ",
		" 429 ",
		" 500 ",
		" 501 ",
		" 502 ",
		" 503 ",
		" 504 ",
	} {
		if strings.Contains(raw, marker) {
			return "generic http edge response on high port"
		}
	}
	return ""
}

func hasUsefulFingerprintMetadata(fingerprint *FingerPrint) bool {
	if fingerprint == nil {
		return false
	}
	if hasStrongFingerprintMetadata(fingerprint) {
		return true
	}
	return fingerprint.ProductName != ""
}

func hasStrongFingerprintMetadata(fingerprint *FingerPrint) bool {
	if fingerprint == nil {
		return false
	}
	return normalizeFingerprintField(fingerprint.Version) != "" ||
		normalizeFingerprintField(fingerprint.Info) != "" ||
		normalizeFingerprintField(fingerprint.Hostname) != "" ||
		normalizeFingerprintField(fingerprint.OperatingSystem) != "" ||
		normalizeFingerprintField(fingerprint.DeviceType) != ""
}

func isGenericHTTPProduct(product string) bool {
	product = strings.ToLower(product)
	return strings.Contains(product, "tengine") ||
		strings.Contains(product, "nginx") ||
		strings.Contains(product, "openresty")
}

func normalizeFingerprintField(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "", "cpe:":
		return ""
	default:
		return value
	}
}

func detectRepeatedHTTPNoiseReasons(results []BatchPortResult, options normalizedBatchScanOptions) map[int]string {
	type signatureGroup struct {
		reason string
		ports  []int
	}

	grouped := make(map[string]signatureGroup)
	for _, result := range results {
		signature, reason := buildRepeatedHTTPNoiseSignature(result, options)
		if signature == "" {
			continue
		}
		group := grouped[signature]
		group.reason = reason
		group.ports = append(group.ports, result.Port)
		grouped[signature] = group
	}

	reasonsByPort := make(map[int]string)
	for _, group := range grouped {
		if len(group.ports) < minRepeatedHTTPNoisePorts {
			continue
		}
		for _, port := range group.ports {
			reasonsByPort[port] = group.reason
		}
	}
	return reasonsByPort
}

func buildRepeatedHTTPNoiseSignature(result BatchPortResult, options normalizedBatchScanOptions) (string, string) {
	if result.Port < options.suspiciousHighPortStart {
		return "", ""
	}
	if result.Status != Matched && result.Status != NotMatched {
		return "", ""
	}
	if result.Response == nil || result.Response.Raw == "" {
		return "", ""
	}

	fingerprint := result.Response.FingerPrint
	if fingerprint == nil {
		return "", ""
	}
	if hasStrongFingerprintMetadata(fingerprint) {
		return "", ""
	}
	if fingerprint.ProductName != "" && !isGenericHTTPProduct(fingerprint.ProductName) {
		return "", ""
	}
	switch fingerprint.Service {
	case "http", "ssl/http", "http-proxy":
	default:
		return "", ""
	}

	raw := strings.ToLower(result.Response.Raw)
	if !strings.HasPrefix(raw, "http/1.") && !strings.HasPrefix(raw, "http/2") {
		return "", ""
	}

	statusCode := extractHTTPStatusCode(raw)
	if statusCode < 400 || statusCode > 599 {
		return "", ""
	}

	serverHeader := extractHTTPHeader(raw, "server:")
	if serverHeader == "" {
		return "", ""
	}
	if serverHeader == "tengine" && statusCode == 410 {
		return "", ""
	}
	return serverHeader + "|" + statusCodeCategory(statusCode), "repeated generic http edge response on high port"
}

func extractHTTPStatusCode(raw string) int {
	firstLine := raw
	if newline := strings.IndexByte(firstLine, '\n'); newline >= 0 {
		firstLine = firstLine[:newline]
	}
	fields := strings.Fields(firstLine)
	if len(fields) < 2 {
		return 0
	}
	code := 0
	for _, ch := range fields[1] {
		if ch < '0' || ch > '9' {
			return 0
		}
		code = code*10 + int(ch-'0')
	}
	return code
}

func extractHTTPHeader(raw, header string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, header) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, header))
		if slash := strings.IndexByte(value, '/'); slash >= 0 {
			value = value[:slash]
		}
		if semi := strings.IndexByte(value, ';'); semi >= 0 {
			value = value[:semi]
		}
		if space := strings.IndexByte(value, ' '); space >= 0 {
			value = value[:space]
		}
		return value
	}
	return ""
}

func statusCodeCategory(code int) string {
	return string(rune('0' + code/100))
}
