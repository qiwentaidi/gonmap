package gonmap

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	tcpProtocolNumber = 6

	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10

	synSourcePortMin = uint16(49000)
	synSourcePortMax = uint16(58999)
)

var errSYNDiscoveryUnavailable = errors.New("syn discovery unavailable")

var openSYNRawConn = func() (*ipv4.RawConn, error) {
	packetConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	return rawConn, nil
}

type synScanTask struct {
	ip    net.IP
	port  int
	hosts []string
}

type synProbeKey struct {
	ip      string
	srcPort uint16
	dstPort uint16
}

type synPendingProbe struct {
	port  int
	hosts []string
}

type synDiscoveryScanner struct {
	conn       *ipv4.RawConn
	pcap       []*pcap.Handle
	timeout    time.Duration
	rate       int
	nextPort   uint16
	randSource *rand.Rand
	srcIPCache map[string]net.IP

	mu      sync.Mutex
	pending map[synProbeKey]synPendingProbe
	open    map[string]OpenPort

	writeMu sync.Mutex
	done    chan struct{}
	wg      sync.WaitGroup
}

func discoverOpenPortsSYN(hosts []string, ports []int, opts PortDiscoveryOptions) ([]OpenPort, error) {
	hostIPs, fallbackHosts := resolveSYNDiscoveryHosts(hosts, opts.Timeout)
	if len(hostIPs) == 0 {
		return nil, errSYNDiscoveryUnavailable
	}

	tasks := buildSYNScanTasks(hostIPs, ports)
	if len(tasks) == 0 {
		return nil, errSYNDiscoveryUnavailable
	}

	rawConn, err := openSYNRawConn()
	if err != nil {
		return nil, err
	}

	scanner := newSYNDiscoveryScanner(rawConn, opts.Timeout, opts.Rate)
	err = scanner.scan(tasks)
	_ = rawConn.Close()
	if err != nil {
		return nil, err
	}

	openPorts := scanner.openPorts()
	if len(fallbackHosts) > 0 && !opts.DisableSYNFallback {
		openPorts = mergeOpenPorts(openPorts, discoverOpenPortsConnect(fallbackHosts, ports, opts))
	}
	return sortOpenPorts(openPorts), nil
}

func newSYNDiscoveryScanner(conn *ipv4.RawConn, timeout time.Duration, rate int) *synDiscoveryScanner {
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	if rate <= 0 {
		rate = defaultSYNDiscoveryRate
	}
	pcapHandles := openSYNPCAPHandles()
	return &synDiscoveryScanner{
		conn:       conn,
		pcap:       pcapHandles,
		timeout:    timeout,
		rate:       rate,
		nextPort:   synSourcePortMin,
		randSource: rand.New(rand.NewSource(time.Now().UnixNano())),
		srcIPCache: make(map[string]net.IP),
		pending:    make(map[synProbeKey]synPendingProbe),
		open:       make(map[string]OpenPort),
		done:       make(chan struct{}),
	}
}

func (s *synDiscoveryScanner) scan(tasks []synScanTask) error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.recv()
	}()
	for _, handle := range s.pcap {
		s.wg.Add(1)
		go func(handle *pcap.Handle) {
			defer s.wg.Done()
			s.recvPCAP(handle)
		}(handle)
	}

	var firstErr error
	sent := 0
	burstWindow := 10 * time.Millisecond
	burstSize := s.rate / int(time.Second/burstWindow)
	if burstSize < 1 {
		burstSize = 1
	}
	nextWindow := time.Now().Add(burstWindow)
	attemptsInWindow := 0

	for _, task := range tasks {
		if attemptsInWindow >= burstSize {
			if sleep := time.Until(nextWindow); sleep > 0 {
				time.Sleep(sleep)
			}
			now := time.Now()
			for !nextWindow.After(now) {
				nextWindow = nextWindow.Add(burstWindow)
			}
			attemptsInWindow = 0
		}
		attemptsInWindow++
		if err := s.sendSYN(task); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent++
	}
	if sent == 0 {
		s.stopReceivers()
		s.wg.Wait()
		if firstErr != nil {
			return firstErr
		}
		return errSYNDiscoveryUnavailable
	}

	time.Sleep(s.timeout + 100*time.Millisecond)
	s.stopReceivers()
	s.wg.Wait()
	return nil
}

func (s *synDiscoveryScanner) stopReceivers() {
	close(s.done)
	_ = s.conn.SetReadDeadline(time.Now())
	for _, handle := range s.pcap {
		handle.Close()
	}
}

func (s *synDiscoveryScanner) sendSYN(task synScanTask) error {
	srcIP, err := s.localIPv4ForRemote(task.ip)
	if err != nil {
		return err
	}

	srcPort := s.nextSourcePort()
	dstPort := uint16(task.port)
	key := synProbeKey{
		ip:      task.ip.String(),
		srcPort: srcPort,
		dstPort: dstPort,
	}

	s.mu.Lock()
	s.pending[key] = synPendingProbe{
		port:  task.port,
		hosts: append([]string(nil), task.hosts...),
	}
	s.mu.Unlock()

	seq := uint32(s.randSource.Int31())
	segment := buildTCPSegment(srcPort, dstPort, seq, 0, tcpFlagSYN, 64240, srcIP, task.ip)
	header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(segment),
		TTL:      64,
		Protocol: tcpProtocolNumber,
		Flags:    ipv4.DontFragment,
		Src:      srcIP,
		Dst:      task.ip,
	}

	if err := s.writeIPv4(header, segment); err != nil {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *synDiscoveryScanner) localIPv4ForRemote(dst net.IP) (net.IP, error) {
	key := dst.String()
	if srcIP := s.srcIPCache[key]; srcIP != nil {
		return srcIP, nil
	}
	srcIP, err := localIPv4ForRemote(dst, s.timeout)
	if err != nil {
		return nil, err
	}
	s.srcIPCache[key] = srcIP
	return srcIP, nil
}

func (s *synDiscoveryScanner) recv() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		header, payload, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		if header == nil || header.Protocol != tcpProtocolNumber {
			continue
		}
		s.handleTCPPacket(header, payload)
	}
}

func (s *synDiscoveryScanner) handleTCPPacket(header *ipv4.Header, payload []byte) {
	if len(payload) < 20 {
		return
	}
	headerLen := int(payload[12]>>4) * 4
	if headerLen < 20 || headerLen > len(payload) {
		return
	}

	remotePort := binary.BigEndian.Uint16(payload[0:2])
	localPort := binary.BigEndian.Uint16(payload[2:4])
	remoteSeq := binary.BigEndian.Uint32(payload[4:8])
	remoteAck := binary.BigEndian.Uint32(payload[8:12])
	flags := payload[13]
	s.handleTCPResponse(header.Src, header.Dst, remotePort, localPort, remoteSeq, remoteAck, flags)
}

func (s *synDiscoveryScanner) handleTCPResponse(remoteIP, localIP net.IP, remotePort, localPort uint16, remoteSeq, remoteAck uint32, flags uint8) {
	key := synProbeKey{
		ip:      remoteIP.String(),
		srcPort: localPort,
		dstPort: remotePort,
	}

	if flags&tcpFlagSYN != 0 && flags&tcpFlagACK != 0 {
		if pending, ok := s.takePending(key); ok {
			s.addOpenPorts(pending)
			_ = s.sendRST(localIP, remoteIP, localPort, remotePort, remoteSeq, remoteAck)
		}
		return
	}
	if flags&tcpFlagRST != 0 {
		_, _ = s.takePending(key)
	}
}

func (s *synDiscoveryScanner) sendRST(localIP, remoteIP net.IP, localPort, remotePort uint16, remoteSeq, remoteAck uint32) error {
	localIP = localIP.To4()
	remoteIP = remoteIP.To4()
	if localIP == nil || remoteIP == nil {
		return nil
	}

	segment := buildTCPSegment(localPort, remotePort, remoteAck, remoteSeq+1, tcpFlagRST|tcpFlagACK, 0, localIP, remoteIP)
	rstHeader := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(segment),
		TTL:      64,
		Protocol: tcpProtocolNumber,
		Flags:    ipv4.DontFragment,
		Src:      localIP,
		Dst:      remoteIP,
	}
	return s.writeIPv4(rstHeader, segment)
}

func openSYNPCAPHandles() []*pcap.Handle {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}

	handles := make([]*pcap.Handle, 0, len(devices))
	for _, device := range devices {
		handle, err := pcap.OpenLive(device.Name, 65535, false, 100*time.Millisecond)
		if err != nil {
			continue
		}
		if err := handle.SetBPFFilter(synPCAPFilter()); err != nil {
			handle.Close()
			continue
		}
		handles = append(handles, handle)
	}
	return handles
}

func synPCAPFilter() string {
	return "tcp and dst portrange 49000-58999 and ((tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) or (tcp[tcpflags] & tcp-rst != 0))"
}

func (s *synDiscoveryScanner) recvPCAP(handle *pcap.Handle) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) || errors.Is(err, io.EOF) {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipLayer == nil || tcpLayer == nil {
			continue
		}
		ip4, ok := ipLayer.(*layers.IPv4)
		if !ok {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		flags := uint8(0)
		if tcp.SYN {
			flags |= tcpFlagSYN
		}
		if tcp.ACK {
			flags |= tcpFlagACK
		}
		if tcp.RST {
			flags |= tcpFlagRST
		}
		s.handleTCPResponse(ip4.SrcIP, ip4.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Seq, tcp.Ack, flags)
	}
}

func (s *synDiscoveryScanner) writeIPv4(header *ipv4.Header, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteTo(header, payload, nil)
}

func (s *synDiscoveryScanner) nextSourcePort() uint16 {
	port := s.nextPort
	if s.nextPort >= synSourcePortMax {
		s.nextPort = synSourcePortMin
	} else {
		s.nextPort++
	}
	return port
}

func (s *synDiscoveryScanner) takePending(key synProbeKey) (synPendingProbe, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
	}
	return pending, ok
}

func (s *synDiscoveryScanner) addOpenPorts(pending synPendingProbe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, host := range pending.hosts {
		key := host + "\x00" + strconv.Itoa(pending.port)
		if _, exists := s.open[key]; exists {
			continue
		}
		s.open[key] = OpenPort{
			Host: host,
			Port: pending.port,
		}
	}
}

func (s *synDiscoveryScanner) openPorts() []OpenPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	openPorts := make([]OpenPort, 0, len(s.open))
	for _, openPort := range s.open {
		openPorts = append(openPorts, openPort)
	}
	return openPorts
}

func resolveSYNDiscoveryHosts(hosts []string, timeout time.Duration) ([]struct {
	host string
	ip   net.IP
}, []string) {
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	if timeout < time.Second {
		timeout = time.Second
	}

	resolved := make([]struct {
		host string
		ip   net.IP
	}, 0, len(hosts))
	fallbackHosts := make([]string, 0)
	seen := make(map[string]struct{})

	for _, host := range hosts {
		if host == "" {
			continue
		}
		if parsed := net.ParseIP(host); parsed != nil {
			ip4 := parsed.To4()
			if ip4 == nil {
				fallbackHosts = append(fallbackHosts, host)
				continue
			}
			key := host + "\x00" + ip4.String()
			if _, exists := seen[key]; !exists {
				resolved = append(resolved, struct {
					host string
					ip   net.IP
				}{host: host, ip: ip4})
				seen[key] = struct{}{}
			}
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			fallbackHosts = append(fallbackHosts, host)
			continue
		}

		added := false
		for _, addr := range addrs {
			ip4 := addr.IP.To4()
			if ip4 == nil {
				continue
			}
			key := host + "\x00" + ip4.String()
			if _, exists := seen[key]; exists {
				continue
			}
			resolved = append(resolved, struct {
				host string
				ip   net.IP
			}{host: host, ip: ip4})
			seen[key] = struct{}{}
			added = true
		}
		if !added {
			fallbackHosts = append(fallbackHosts, host)
		}
	}
	return resolved, fallbackHosts
}

func buildSYNScanTasks(hostIPs []struct {
	host string
	ip   net.IP
}, ports []int) []synScanTask {
	taskByKey := make(map[string]*synScanTask)
	order := make([]string, 0, len(hostIPs)*len(ports))

	for _, hostIP := range hostIPs {
		for _, port := range ports {
			if !isValidPort(port) {
				continue
			}
			key := hostIP.ip.String() + "\x00" + strconv.Itoa(port)
			task := taskByKey[key]
			if task == nil {
				task = &synScanTask{
					ip:   hostIP.ip,
					port: port,
				}
				taskByKey[key] = task
				order = append(order, key)
			}
			if !containsString(task.hosts, hostIP.host) {
				task.hosts = append(task.hosts, hostIP.host)
			}
		}
	}

	tasks := make([]synScanTask, 0, len(order))
	for _, key := range order {
		tasks = append(tasks, *taskByKey[key])
	}
	return tasks
}

func localIPv4ForRemote(dst net.IP, timeout time.Duration) (net.IP, error) {
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(dst.String(), "80"), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return nil, errSYNDiscoveryUnavailable
	}
	srcIP := localAddr.IP.To4()
	if srcIP == nil {
		return nil, errSYNDiscoveryUnavailable
	}
	return srcIP, nil
}

func buildTCPSegment(srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, srcIP, dstIP net.IP) []byte {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], srcPort)
	binary.BigEndian.PutUint16(segment[2:4], dstPort)
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], window)
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksum(srcIP, dstIP, segment))
	return segment
}

func tcpChecksum(srcIP, dstIP net.IP, segment []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	sum := uint32(0)
	sum = addChecksumBytes(sum, src)
	sum = addChecksumBytes(sum, dst)
	sum += uint32(tcpProtocolNumber)
	sum += uint32(len(segment))
	sum = addChecksumBytes(sum, segment)

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func addChecksumBytes(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func mergeOpenPorts(left, right []OpenPort) []OpenPort {
	merged := make([]OpenPort, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, item := range append(left, right...) {
		key := item.Host + "\x00" + strconv.Itoa(item.Port)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, item)
	}
	return merged
}

func sortOpenPorts(openPorts []OpenPort) []OpenPort {
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Host != openPorts[j].Host {
			return openPorts[i].Host < openPorts[j].Host
		}
		return openPorts[i].Port < openPorts[j].Port
	})
	return openPorts
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
