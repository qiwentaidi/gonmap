//go:build benchscan

package lib

import (
	"context"
	"flag"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	benchBatchTarget             = flag.String("target", "127.0.0.1", "target host for batch scan speed measurement")
	benchBatchStartPort          = flag.Int("start-port", 1, "start port for batch scan speed measurement")
	benchBatchEndPort            = flag.Int("end-port", 65535, "end port for batch scan speed measurement")
	benchBatchDiscoveryMode      = flag.String("discovery-mode", "connect", "discovery mode: connect or syn")
	benchBatchDiscoveryTimeout   = flag.Duration("discovery-timeout", 10*time.Second, "discovery wait/timeout")
	benchBatchDiscoveryRate      = flag.Int("discovery-rate", 3000, "syn discovery packet rate")
	benchBatchDiscoveryWorkers   = flag.Int("discovery-workers", 4096, "connect discovery concurrency")
	benchBatchFingerprintTimeout = flag.Duration("fingerprint-timeout", 3*time.Second, "per-port fingerprint timeout")
	benchBatchFingerprintWorkers = flag.Int("fingerprint-workers", 64, "fingerprint worker count")
)

func TestMeasureBatchScanSpeed(t *testing.T) {
	ports := ExpandPortRange(*benchBatchStartPort, *benchBatchEndPort)
	if len(ports) == 0 {
		t.Fatalf("empty port range: %d-%d", *benchBatchStartPort, *benchBatchEndPort)
	}

	discoveryMode := PortDiscoveryModeConnect
	if *benchBatchDiscoveryMode == string(PortDiscoveryModeSYN) {
		discoveryMode = PortDiscoveryModeSYN
	}

	sdk := New(nil)
	start := time.Now()
	options := &BatchScanOptions{
		DiscoveryOptions: PortDiscoveryOptions{
			Timeout:     *benchBatchDiscoveryTimeout,
			Concurrency: *benchBatchDiscoveryWorkers,
			Mode:        discoveryMode,
			Rate:        *benchBatchDiscoveryRate,
		},
		FingerprintOptions: ScanOptions{
			Timeout:  *benchBatchFingerprintTimeout,
			Protocol: ScanProtocolTCP,
		},
		FingerprintWorkers: *benchBatchFingerprintWorkers,
	}
	normalized := normalizeBatchScanOptions(options)

	discoveryStart := time.Now()
	openPorts := sdk.DiscoverOpenPorts([]string{*benchBatchTarget}, ports, &normalized.discoveryOptions)
	discoveryElapsed := time.Since(discoveryStart)

	groupedOpen := map[string][]int{
		*benchBatchTarget: extractBenchPorts(openPorts, *benchBatchTarget),
	}
	fingerprintStart := time.Now()
	groupedResults := sdk.identifyOpenPorts(context.Background(), groupedOpen, normalized)
	fingerprintElapsed := time.Since(fingerprintStart)

	result := AnalyzeHostResults(*benchBatchTarget, groupedOpen[*benchBatchTarget], groupedResults[*benchBatchTarget], options)
	elapsed := time.Since(start)

	matched := 0
	services := make([]string, 0, len(result.Results))
	for _, item := range result.Results {
		if item.Status == Matched {
			matched++
		}
		if item.Response == nil || item.Response.FingerPrint == nil || item.Response.FingerPrint.Service == "" {
			continue
		}
		services = append(services, formatBenchService(item))
	}

	t.Logf(
		"target=%s discovery_mode=%s ports=%d range=%d-%d open=%d results=%d matched=%d elapsed=%s discovery_elapsed=%s fingerprint_elapsed=%s ports_per_second=%.0f discovery_timeout=%s discovery_rate=%d discovery_workers=%d fingerprint_timeout=%s fingerprint_workers=%d services=%s",
		*benchBatchTarget,
		discoveryMode,
		len(ports),
		*benchBatchStartPort,
		*benchBatchEndPort,
		len(result.OpenPorts),
		len(result.Results),
		matched,
		elapsed,
		discoveryElapsed,
		fingerprintElapsed,
		float64(len(ports))/elapsed.Seconds(),
		*benchBatchDiscoveryTimeout,
		*benchBatchDiscoveryRate,
		*benchBatchDiscoveryWorkers,
		*benchBatchFingerprintTimeout,
		*benchBatchFingerprintWorkers,
		strings.Join(services, ","),
	)
}

func extractBenchPorts(openPorts []OpenPort, host string) []int {
	ports := make([]int, 0, len(openPorts))
	for _, openPort := range openPorts {
		if openPort.Host != host {
			continue
		}
		ports = append(ports, openPort.Port)
	}
	return ports
}

func formatBenchService(item BatchPortResult) string {
	fingerprint := item.Response.FingerPrint
	service := fingerprint.Service
	if fingerprint.ProductName != "" {
		service += "/" + fingerprint.ProductName
	}
	return strings.TrimPrefix(strings.Join([]string{strconv.Itoa(item.Port), service}, ":"), ":")
}
