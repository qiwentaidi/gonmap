package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qiwentaidi/gonmap/lib"
)

func main() {
	timeout := flag.Duration("timeout", 4*time.Second, "per-target scan timeout")
	readSize := flag.Int("read-size", 4096, "max response bytes to read")
	showRaw := flag.Bool("show-raw", false, "print raw response preview")
	rawLimit := flag.Int("raw-limit", 128, "max raw response bytes to print")
	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		fmt.Println("usage: go run ./cmd/batch_scan -- host:port [host:port ...]")
		return
	}

	sdk := lib.New(&lib.Options{
		Timeout:  *timeout,
		Protocol: lib.ScanProtocolTCP,
		ReadSize: *readSize,
	})

	for _, target := range targets {
		host, port, ok := strings.Cut(target, ":")
		if !ok {
			fmt.Printf("%s -> invalid target\n", target)
			continue
		}

		var portNum int
		if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
			fmt.Printf("%s -> invalid port\n", target)
			continue
		}

		status, resp := sdk.Scan(host, portNum, nil)
		service := ""
		product := ""
		version := ""
		probe := ""
		rawHex := ""
		rawText := ""
		if resp != nil && resp.FingerPrint != nil {
			service = resp.FingerPrint.Service
			product = resp.FingerPrint.ProductName
			version = resp.FingerPrint.Version
			probe = resp.FingerPrint.ProbeName
		}
		if *showRaw && resp != nil && len(resp.Raw) > 0 {
			limit := min(*rawLimit, len(resp.Raw))
			raw := []byte(resp.Raw[:limit])
			rawHex = fmt.Sprintf("%x", raw)
			rawText = strconv.QuoteToASCII(string(raw))
		}

		fmt.Printf("%s -> status=%s service=%s product=%s version=%s probe=%s\n",
			target, status.String(), service, product, version, probe)
		if *showRaw {
			fmt.Printf("  raw_len=%d raw_hex=%s raw_text=%s\n", len(safeRaw(resp)), rawHex, rawText)
		}
	}
}

func safeRaw(resp *lib.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Raw
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
