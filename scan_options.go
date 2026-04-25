package gonmap

import "time"

const (
	defaultScanTimeout = time.Second
	defaultReadSize    = 10240
)

type ScanProtocol string

const (
	ScanProtocolAuto ScanProtocol = "auto"
	ScanProtocolTCP  ScanProtocol = "tcp"
	ScanProtocolUDP  ScanProtocol = "udp"
)

type ScanOptions struct {
	Timeout      time.Duration
	ProxyURL     string
	ReadSize     int
	DeepIdentify bool
	DisableFingerprint bool
	Protocol     ScanProtocol
}

func (n *Nmap) normalizeScanOptions(options *ScanOptions) ScanOptions {
	normalized := n.defaultScanOptions
	if options == nil {
		if normalized.Timeout <= 0 {
			normalized.Timeout = defaultScanTimeout
		}
		if normalized.ReadSize <= 0 {
			normalized.ReadSize = defaultReadSize
		}
		return normalized
	}

	if options.Timeout > 0 {
		normalized.Timeout = options.Timeout
	}
	if options.ProxyURL != "" {
		normalized.ProxyURL = options.ProxyURL
	}
	if options.ReadSize > 0 {
		normalized.ReadSize = options.ReadSize
	}
	if options.DeepIdentify {
		normalized.DeepIdentify = true
	}
	if options.DisableFingerprint {
		normalized.DisableFingerprint = true
	}
	if options.Protocol != "" {
		normalized.Protocol = options.Protocol
	}
	if normalized.Timeout <= 0 {
		normalized.Timeout = defaultScanTimeout
	}
	if normalized.ReadSize <= 0 {
		normalized.ReadSize = defaultReadSize
	}
	if normalized.Protocol == "" {
		normalized.Protocol = ScanProtocolAuto
	}
	return normalized
}
