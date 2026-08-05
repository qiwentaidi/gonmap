package gonmap

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	arrayutil "github.com/qiwentaidi/utils/array"
)

type ScanSession struct {
	ctx       context.Context
	engine    *Nmap
	host      string
	port      int
	options   ScanOptions
	probeUsed map[string]struct{}
}

func newScanSession(engine *Nmap, host string, port int, options ScanOptions) *ScanSession {
	return newScanSessionWithContext(context.Background(), engine, host, port, options)
}

func newScanSessionWithContext(ctx context.Context, engine *Nmap, host string, port int, options ScanOptions) *ScanSession {
	if ctx == nil {
		ctx = context.Background()
	}
	return &ScanSession{
		ctx:       ctx,
		engine:    engine,
		host:      host,
		port:      port,
		options:   options,
		probeUsed: make(map[string]struct{}),
	}
}

func (s *ScanSession) scan() (status Status, response *Response) {
	if s.ctx.Err() != nil {
		return Closed, nil
	}
	if s.options.DisableFingerprint && s.canUseLightweightOpenCheck() {
		return s.scanOpenOnly()
	}
	if s.shouldRunLightweightOpenCheck() {
		status, response = s.scanOpenOnly()
		if status == Closed {
			return Closed, nil
		}
		if s.ctx.Err() != nil {
			return Closed, nil
		}
	}

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

func (s *ScanSession) scanOpenOnly() (Status, *Response) {
	timeout := s.options.Timeout
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", net.JoinHostPort(s.host, strconv.Itoa(s.port)))
	if err != nil {
		return Closed, nil
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_ = conn.Close()
	return Open, nil
}

func (s *ScanSession) shouldRunLightweightOpenCheck() bool {
	return !s.options.DisableFingerprint && s.canUseLightweightOpenCheck()
}

func (s *ScanSession) canUseLightweightOpenCheck() bool {
	return s.options.Protocol != ScanProtocolUDP && s.options.ProxyURL == ""
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
			return s.refineMatchedResponse(Matched, response)
		}
	}
	return s.refineMatchedResponse(status, response)
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

func (s *ScanSession) refineMatchedResponse(status Status, response *Response) (Status, *Response) {
	if status != Matched {
		return status, response
	}

	if s.shouldRefineHTTPS(response) {
		refinedStatus, refinedResponse := s.getResponseByHTTPS()
		if refinedStatus == Matched && refinedResponse != nil && refinedResponse.FingerPrint != nil {
			if refinedResponse.FingerPrint.Service == "http" {
				refinedResponse.FingerPrint.Service = "https"
			}
			if refinedResponse.FingerPrint.Service == "https" {
				return refinedStatus, refinedResponse
			}
		}
	}

	if s.shouldRefineEtcd(response) {
		etcdProbe := s.engine.probeNameMap["TCP_ETCD_VERSION"]
		if etcdProbe != nil {
			refinedStatus, refinedResponse := s.getResponse(response.TLS, etcdProbe)
			if refinedStatus == Matched && refinedResponse != nil && refinedResponse.FingerPrint != nil &&
				refinedResponse.FingerPrint.Service == "etcd-client" {
				return refinedStatus, refinedResponse
			}
		}
	}

	if s.shouldRefineDocker(response) {
		dockerProbe := s.engine.probeNameMap["TCP_docker"]
		if dockerProbe == nil {
			return status, response
		}

		refinedStatus, refinedResponse := s.getResponse(response.TLS, dockerProbe)
		if refinedStatus == Matched && refinedResponse != nil && refinedResponse.FingerPrint != nil &&
			refinedResponse.FingerPrint.ProductName != "" {
			return refinedStatus, refinedResponse
		}
	}
	return status, response
}

func (s *ScanSession) shouldRefineDocker(response *Response) bool {
	return response != nil &&
		response.FingerPrint != nil &&
		response.FingerPrint.Service == "docker" &&
		response.FingerPrint.ProductName == ""
}

func (s *ScanSession) shouldRefineHTTPS(response *Response) bool {
	return response != nil &&
		response.FingerPrint != nil &&
		response.FingerPrint.Service == "http" &&
		(strings.Contains(response.Raw, "Client sent an HTTP request to an HTTPS server.") ||
			strings.Contains(response.Raw, "The plain HTTP request was sent to HTTPS port") ||
			strings.Contains(response.Raw, "You're speaking plain HTTP to an SSL-enabled server port"))
}

func (s *ScanSession) shouldRefineEtcd(response *Response) bool {
	return response != nil &&
		response.FingerPrint != nil &&
		(response.FingerPrint.Service == "http" || response.FingerPrint.Service == "https") &&
		response.FingerPrint.ProductName == "" &&
		strings.Contains(response.Raw, "Access-Control-Allow-Headers: accept, content-type, authorization") &&
		strings.Contains(response.Raw, "page not found")
}

func (s *ScanSession) getResponseByProbes(probes ...string) (status Status, response *Response) {
	var responseNotMatch *Response
	for _, requestName := range probes {
		if s.ctx.Err() != nil {
			return Closed, nil
		}
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
	if s.ctx.Err() != nil {
		return Closed, nil
	}
	if s.port == 53 && p.protocol == "UDP" {
		if DnsScanContext(s.ctx, s.host, s.port) {
			return Matched, &dnsResponse
		}
		return Closed, nil
	}

	text, tls, err := p.scanWithContext(s.ctx, s.host, s.port, tls, s.options.Timeout, s.options.ReadSize, s.options.ProxyURL)
	if err != nil {
		if s.ctx.Err() != nil {
			return Closed, nil
		}
		if strings.Contains(err.Error(), "STEP1") {
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
	enrichFingerprintByProbe(p.name, text, fingerPrint)
	enrichFingerprintByPort(s.port, fingerPrint)
	response.FingerPrint = fingerPrint

	if fingerPrint.Service == "" {
		return NotMatched, response
	}
	return Matched, response
}

func enrichFingerprintByProbe(probeName string, responseRaw string, fingerPrint *FingerPrint) {
	if fingerPrint == nil || fingerPrint.Service != "" {
		return
	}
	if probeName == "TCP_Kafka" && looksLikeKafkaMetadata(responseRaw) {
		fingerPrint.Service = "kafka"
		fingerPrint.ProductName = "Kafka"
	}
}

func enrichFingerprintByPort(port int, fingerPrint *FingerPrint) {
	if fingerPrint == nil {
		return
	}

	if port == 54321 && fingerPrint.Service == "postgresql" &&
		(fingerPrint.ProductName == "" || fingerPrint.ProductName == "PostgreSQL DB" || fingerPrint.ProductName == "KingbaseES") {
		fingerPrint.Service = "kingbase"
		fingerPrint.ProductName = "KingbaseES"
	}
}

func looksLikeKafkaMetadata(raw string) bool {
	data := []byte(raw)
	if len(data) < 18 {
		return false
	}

	payloadSize := int(binary.BigEndian.Uint32(data[0:4]))
	if payloadSize <= 0 {
		return false
	}

	offset := 8 // size + correlation id
	brokerCount := int(int32(binary.BigEndian.Uint32(data[offset : offset+4])))
	offset += 4
	if brokerCount <= 0 || brokerCount > 128 {
		return false
	}

	parsedBrokers := 0
	for i := 0; i < brokerCount && i < 3; i++ {
		if offset+6 > len(data) {
			return false
		}
		offset += 4 // node id

		hostLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if hostLen <= 0 || hostLen > 255 || offset+hostLen+4 > len(data) {
			return false
		}
		host := data[offset : offset+hostLen]
		if !looksLikeKafkaHost(host) {
			return false
		}
		offset += hostLen

		port := int(int32(binary.BigEndian.Uint32(data[offset : offset+4])))
		offset += 4
		if port <= 0 || port > 65535 {
			return false
		}

		if offset+2 <= len(data) {
			rackLen := int(int16(binary.BigEndian.Uint16(data[offset : offset+2])))
			offset += 2
			if rackLen >= 0 {
				if rackLen > 255 || offset+rackLen > len(data) {
					return false
				}
				offset += rackLen
			}
		}
		parsedBrokers++
	}

	return parsedBrokers > 0
}

func looksLikeKafkaHost(host []byte) bool {
	if len(host) == 0 {
		return false
	}
	for _, b := range host {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '.', '-', '_', ':':
			continue
		default:
			return false
		}
	}
	return true
}
