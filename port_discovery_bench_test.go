//go:build benchscan

package gonmap

import (
	"flag"
	"testing"
	"time"
)

var (
	benchTarget      = flag.String("target", "127.0.0.1", "target host for discovery speed measurement")
	benchStartPort   = flag.Int("start-port", 1, "start port for discovery speed measurement")
	benchEndPort     = flag.Int("end-port", 65535, "end port for discovery speed measurement")
	benchMode        = flag.String("mode", "connect", "discovery mode: connect or syn")
	benchTimeout     = flag.Duration("timeout", 800*time.Millisecond, "per-port discovery timeout")
	benchConcurrency = flag.Int("concurrency", 4096, "connect discovery concurrency")
	benchRate        = flag.Int("rate", 3000, "syn discovery packet rate")
)

func TestMeasureDiscoverySpeed(t *testing.T) {
	ports := ExpandPortRange(*benchStartPort, *benchEndPort)
	if len(ports) == 0 {
		t.Fatalf("empty port range: %d-%d", *benchStartPort, *benchEndPort)
	}

	mode := PortDiscoveryModeConnect
	if *benchMode == string(PortDiscoveryModeSYN) {
		mode = PortDiscoveryModeSYN
	}

	options := &PortDiscoveryOptions{
		Timeout:     *benchTimeout,
		Concurrency: *benchConcurrency,
		Mode:        mode,
		Rate:        *benchRate,
	}

	start := time.Now()
	var (
		openPorts []OpenPort
		err       error
	)
	if mode == PortDiscoveryModeSYN {
		openPorts, err = discoverOpenPortsSYN([]string{*benchTarget}, ports, *options)
		if err != nil {
			t.Fatalf("syn discovery failed: %v", err)
		}
	} else {
		openPorts = DiscoverOpenPorts([]string{*benchTarget}, ports, options)
	}
	elapsed := time.Since(start)
	portsPerSecond := float64(len(ports)) / elapsed.Seconds()

	t.Logf(
		"target=%s mode=%s ports=%d range=%d-%d open=%d elapsed=%s ports_per_second=%.0f timeout=%s concurrency=%d rate=%d",
		*benchTarget,
		mode,
		len(ports),
		*benchStartPort,
		*benchEndPort,
		len(openPorts),
		elapsed,
		portsPerSecond,
		*benchTimeout,
		*benchConcurrency,
		*benchRate,
	)
}
