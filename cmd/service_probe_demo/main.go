package main

import (
	"fmt"
	"time"

	"github.com/qiwentaidi/gonmap/lib"
)

func main() {
	sdk := lib.New(&lib.Options{
		Timeout:  60 * time.Second,
		Protocol: lib.ScanProtocolTCP,
	})
	fmt.Println("Testing Dameng Database Detection on 139.199.81.233:5236")
	fmt.Println("Using SDK default timeout: 60 seconds...")

	status, resp := sdk.Scan("139.199.81.233", 5236, nil)
	fmt.Printf("Status: %v\n", status)

	if resp == nil {
		fmt.Println("Response is nil - no data received or connection failed")
		fmt.Println("\nPossible reasons:")
		fmt.Println("1. Connection timeout")
		fmt.Println("2. No response from server")
		fmt.Println("3. Probe packets not matching expected format")
		return
	}

	fmt.Printf("\n=== Response Details ===\n")
	if len(resp.Raw) > 0 {
		fmt.Printf("Raw response length: %d bytes\n", len(resp.Raw))
		fmt.Printf("Raw response (first 200 bytes, hex): %x\n", resp.Raw[:min(200, len(resp.Raw))])
		fmt.Printf("Raw response (first 200 bytes, ascii): %q\n", resp.Raw[:min(200, len(resp.Raw))])
	} else {
		fmt.Println("No raw response data")
	}

	fmt.Printf("\n=== Fingerprint ===\n")
	if resp.FingerPrint != nil {
		fmt.Printf("Service: %v\n", resp.FingerPrint.Service)
		fmt.Printf("Product: %v\n", resp.FingerPrint.ProductName)
		fmt.Printf("Version: %v\n", resp.FingerPrint.Version)
		fmt.Printf("Info: %v\n", resp.FingerPrint.Info)
		fmt.Printf("Hostname: %v\n", resp.FingerPrint.Hostname)
		fmt.Printf("OperatingSystem: %v\n", resp.FingerPrint.OperatingSystem)
		fmt.Printf("DeviceType: %v\n", resp.FingerPrint.DeviceType)
	} else {
		fmt.Println("No fingerprint data")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
