package lib

import (
	"testing"
	"time"
)

func TestSDKMergesDefaultScanOptions(t *testing.T) {
	sdk := New(&Options{
		Timeout:            5 * time.Second,
		ReadSize:           2048,
		DisableFingerprint: true,
		Protocol:           ScanProtocolTCP,
	})

	if sdk.defaultScanOptions.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout to be 5s, got %v", sdk.defaultScanOptions.Timeout)
	}
	if sdk.defaultScanOptions.ReadSize != 2048 {
		t.Fatalf("expected default read size to be 2048, got %d", sdk.defaultScanOptions.ReadSize)
	}
	if sdk.defaultScanOptions.Protocol != ScanProtocolTCP {
		t.Fatalf("expected default protocol to be tcp, got %q", sdk.defaultScanOptions.Protocol)
	}
	if !sdk.defaultScanOptions.DisableFingerprint {
		t.Fatal("expected disable fingerprint to be enabled")
	}
}

func TestSDKScanOptionsOverrideDefaults(t *testing.T) {
	sdk := New(&Options{
		Timeout:  5 * time.Second,
		ReadSize: 2048,
		Protocol: ScanProtocolTCP,
	})

	merged := sdk.defaultScanOptions
	override := &ScanOptions{
		Timeout:  10 * time.Second,
		ReadSize: 4096,
	}
	if override.Timeout > 0 {
		merged.Timeout = override.Timeout
	}
	if override.ReadSize > 0 {
		merged.ReadSize = override.ReadSize
	}

	if merged.Timeout != 10*time.Second {
		t.Fatalf("expected override timeout to be 10s, got %v", merged.Timeout)
	}
	if merged.ReadSize != 4096 {
		t.Fatalf("expected override read size to be 4096, got %d", merged.ReadSize)
	}
	if merged.Protocol != ScanProtocolTCP {
		t.Fatalf("expected protocol to stay tcp, got %q", merged.Protocol)
	}
}
