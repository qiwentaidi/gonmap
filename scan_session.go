package gonmap

import (
	"strings"

	arrayutil "github.com/qiwentaidi/utils/array"
)

type ScanSession struct {
	engine    *Nmap
	host      string
	port      int
	options   ScanOptions
	probeUsed map[string]struct{}
}

func newScanSession(engine *Nmap, host string, port int, options ScanOptions) *ScanSession {
	return &ScanSession{
		engine:    engine,
		host:      host,
		port:      port,
		options:   options,
		probeUsed: make(map[string]struct{}),
	}
}

func (s *ScanSession) scan() (status Status, response *Response) {
	probeNames := s.resolveProbeNames()
	if len(probeNames) == 0 {
		return Unknown, &Response{}
	}

	firstProbe := probeNames[0]
	status, response = s.getRealResponse(firstProbe)
	if status == Closed || status == Matched {
		return status, response
	}
	status, response = s.getRealResponse(probeNames[1:]...)
	return status, response
}

func (s *ScanSession) resolveProbeNames() []string {
	var probeNames []string
	if s.options.DeepIdentify {
		probeNames = append(probeNames, s.filterProbeNames(s.engine.probeSort)...)
	} else if s.options.Protocol == ScanProtocolUDP {
		probeNames = append(probeNames, s.filterProbeNames(s.engine.portProbeMap[s.port])...)
	} else if arrayutil.ArrayContains(s.port, s.engine.bypassAllProbePort) {
		probeNames = append(probeNames, s.filterProbeNames(s.engine.portProbeMap[s.port])...)
		probeNames = append(probeNames, s.filterProbeNames(s.engine.allProbeMap)...)
	} else {
		probeNames = append(probeNames, s.filterProbeNames(s.engine.allProbeMap)...)
		probeNames = append(probeNames, s.filterProbeNames(s.engine.portProbeMap[s.port])...)
	}
	if s.options.Protocol != ScanProtocolUDP {
		probeNames = append(probeNames, s.filterProbeNames(s.engine.sslProbeMap)...)
	}
	return arrayutil.RemoveDuplicates(probeNames)
}

func (s *ScanSession) filterProbeNames(probeNames []string) []string {
	filtered := make([]string, 0, len(probeNames))
	for _, requestName := range probeNames {
		p := s.engine.probeNameMap[requestName]
		if p == nil {
			continue
		}
		if !s.shouldUseProbe(p) {
			continue
		}
		filtered = append(filtered, requestName)
	}
	return filtered
}

func (s *ScanSession) shouldUseProbe(p *probe) bool {
	switch s.options.Protocol {
	case ScanProtocolTCP:
		return p.protocol == "TCP"
	case ScanProtocolUDP:
		return p.protocol == "UDP"
	default:
		return true
	}
}

func (s *ScanSession) getRealResponse(probes ...string) (status Status, response *Response) {
	status, response = s.getResponseByProbes(probes...)
	if status != Matched {
		return status, response
	}
	if s.options.Protocol == ScanProtocolUDP {
		return status, response
	}
	if response.FingerPrint.Service == "ssl" {
		status, response := s.getResponseBySSLSecondProbes()
		if status == Matched {
			return Matched, response
		}
	}
	return status, response
}

func (s *ScanSession) getResponseBySSLSecondProbes() (status Status, response *Response) {
	status, response = s.getResponseByProbes(s.engine.sslSecondProbeMap...)
	if status != Matched || response.FingerPrint.Service == "ssl" {
		status, response = s.getResponseByHTTPS()
	}
	if status == Matched && response.FingerPrint.Service != "ssl" {
		if response.FingerPrint.Service == "http" {
			response.FingerPrint.Service = "https"
		}
		return Matched, response
	}
	return NotMatched, response
}

func (s *ScanSession) getResponseByHTTPS() (status Status, response *Response) {
	httpRequest := s.engine.probeNameMap["TCP_GetRequest"]
	return s.getResponse(true, httpRequest)
}

func (s *ScanSession) getResponseByProbes(probes ...string) (status Status, response *Response) {
	var responseNotMatch *Response
	for _, requestName := range probes {
		if _, ok := s.probeUsed[requestName]; ok {
			continue
		}
		s.probeUsed[requestName] = struct{}{}
		p := s.engine.probeNameMap[requestName]
		if p == nil {
			continue
		}

		status, response = s.getResponse(arrayutil.ArrayContains(s.port, p.sslports), p)
		if status == Closed || status == Matched {
			responseNotMatch = nil
			break
		}
		if status == NotMatched {
			responseNotMatch = response
		}
	}
	if responseNotMatch != nil {
		response = responseNotMatch
	}
	return status, response
}

func (s *ScanSession) getResponse(tls bool, p *probe) (Status, *Response) {
	if s.port == 53 && p.protocol == "UDP" {
		if DnsScan(s.host, s.port) {
			return Matched, &dnsResponse
		}
		return Closed, nil
	}

	text, tls, err := p.scan(s.host, s.port, tls, s.options.Timeout, s.options.ReadSize, s.options.ProxyURL)
	if err != nil {
		if strings.Contains(err.Error(), "STEP1") {
			return Closed, nil
		}
		if strings.Contains(err.Error(), "STEP2") {
			return Closed, nil
		}
		if p.protocol == "UDP" && strings.Contains(err.Error(), "refused") {
			return Closed, nil
		}
		return Open, nil
	}

	response := &Response{
		Raw:         text,
		TLS:         tls,
		FingerPrint: &FingerPrint{},
	}
	fingerPrint := s.engine.getFinger(text, tls, p.name)
	response.FingerPrint = fingerPrint

	if fingerPrint.Service == "" {
		return NotMatched, response
	}
	return Matched, response
}
