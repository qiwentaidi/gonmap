package lib

import (
	"time"

	"github.com/qiwentaidi/gonmap"
)

type Status = gonmap.Status
type Response = gonmap.Response
type FingerPrint = gonmap.FingerPrint
type ScanOptions = gonmap.ScanOptions
type ScanProtocol = gonmap.ScanProtocol
type PortDiscoveryOptions = gonmap.PortDiscoveryOptions
type PortDiscoveryMode = gonmap.PortDiscoveryMode
type OpenPort = gonmap.OpenPort

const (
	ScanProtocolAuto = gonmap.ScanProtocolAuto
	ScanProtocolTCP  = gonmap.ScanProtocolTCP
	ScanProtocolUDP  = gonmap.ScanProtocolUDP
)

const (
	PortDiscoveryModeConnect = gonmap.PortDiscoveryModeConnect
	PortDiscoveryModeSYN     = gonmap.PortDiscoveryModeSYN
)

const (
	Closed     = gonmap.Closed
	Open       = gonmap.Open
	Matched    = gonmap.Matched
	NotMatched = gonmap.NotMatched
	Unknown    = gonmap.Unknown
)

type Options struct {
	// Filter 控制使用的探针稀有度上限，值越小越偏快速扫描，值越大越偏完整识别。
	Filter int
	// DeepIdentify 表示是否启用更深度的探针识别流程。
	DeepIdentify bool
	// DisableFingerprint 表示只判断端口是否开放，不做协议识别。
	DisableFingerprint bool
	// Timeout 是单个端口扫描的默认超时时间。
	Timeout time.Duration
	// ProxyURL 是默认代理地址，目前主要用于 TCP 扫描。
	ProxyURL string
	// ReadSize 是单次扫描读取响应的默认最大字节数。
	ReadSize int
	// Protocol 指定默认扫描协议，可选 TCP、UDP 或 Auto。
	Protocol ScanProtocol
}

type SDK struct {
	engine             *gonmap.Nmap
	defaultScanOptions ScanOptions
}

func New(options *Options) *SDK {
	if options != nil && options.Filter > 0 {
		gonmap.SetFilter(options.Filter)
	}

	engine := gonmap.New()
	if options != nil && options.DeepIdentify {
		engine.OpenDeepIdentify()
	}

	sdk := &SDK{engine: engine}
	if options != nil {
		sdk.defaultScanOptions = ScanOptions{
			Timeout:            options.Timeout,
			ProxyURL:           options.ProxyURL,
			ReadSize:           options.ReadSize,
			DeepIdentify:       options.DeepIdentify,
			DisableFingerprint: options.DisableFingerprint,
			Protocol:           options.Protocol,
		}
	}

	return sdk
}

func (s *SDK) Scan(host string, port int, options *ScanOptions) (Status, *Response) {
	merged := s.defaultScanOptions
	if options != nil {
		if options.Timeout > 0 {
			merged.Timeout = options.Timeout
		}
		if options.ProxyURL != "" {
			merged.ProxyURL = options.ProxyURL
		}
		if options.ReadSize > 0 {
			merged.ReadSize = options.ReadSize
		}
		if options.DeepIdentify {
			merged.DeepIdentify = true
		}
		if options.DisableFingerprint {
			merged.DisableFingerprint = true
		}
		if options.Protocol != "" {
			merged.Protocol = options.Protocol
		}
	}
	return s.engine.ScanWithOptions(host, port, &merged)
}

func (s *SDK) Engine() *gonmap.Nmap {
	return s.engine
}

func (s *SDK) DiscoverOpenPorts(hosts []string, ports []int, options *PortDiscoveryOptions) []OpenPort {
	return gonmap.DiscoverOpenPorts(hosts, ports, options)
}

func ExpandPortRange(startPort, endPort int) []int {
	return gonmap.ExpandPortRange(startPort, endPort)
}
