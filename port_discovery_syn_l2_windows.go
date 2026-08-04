//go:build windows

package gonmap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	netroute "github.com/libp2p/go-netroute"
)

type synLayer2PacketSender struct {
	timeout time.Duration
	opts    gopacket.SerializeOptions

	mu     sync.Mutex
	routes map[string]*synLayer2Route
}

type synLayer2Route struct {
	handle *pcap.Handle
	srcIP  net.IP
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
}

func newSYNLayer2PacketSender(timeout time.Duration) (synPacketSender, error) {
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	if _, err := pcap.FindAllDevs(); err != nil {
		return nil, err
	}
	return &synLayer2PacketSender{
		timeout: timeout,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		routes: make(map[string]*synLayer2Route),
	}, nil
}

func (s *synLayer2PacketSender) sendTCP(remoteIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16) (net.IP, error) {
	route, err := s.routeForRemote(remoteIP)
	if err != nil {
		return nil, err
	}

	remoteIP = remoteIP.To4()
	if remoteIP == nil {
		return nil, errSYNDiscoveryUnavailable
	}

	eth := &layers.Ethernet{
		SrcMAC:       route.srcMAC,
		DstMAC:       route.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       uint16(time.Now().UnixNano()),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    route.srcIP,
		DstIP:    remoteIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		Window:  window,
		SYN:     flags&tcpFlagSYN != 0,
		ACK:     flags&tcpFlagACK != 0,
		RST:     flags&tcpFlagRST != 0,
	}
	tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.opts, eth, ip4, tcp); err != nil {
		return nil, err
	}

	s.mu.Lock()
	err = route.handle.WritePacketData(buf.Bytes())
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return route.srcIP, nil
}

func (s *synLayer2PacketSender) routeForRemote(remoteIP net.IP) (*synLayer2Route, error) {
	remoteIP = remoteIP.To4()
	if remoteIP == nil {
		return nil, errSYNDiscoveryUnavailable
	}

	key := remoteIP.String()
	s.mu.Lock()
	if route := s.routes[key]; route != nil {
		s.mu.Unlock()
		return route, nil
	}
	s.mu.Unlock()

	srcIP, err := localIPv4ForRemote(remoteIP, s.timeout)
	if err != nil {
		return nil, err
	}

	device, address, err := synPCAPDeviceForIPv4(srcIP)
	if err != nil {
		return nil, err
	}

	srcMAC, err := localHardwareAddrForIPv4(srcIP)
	if err != nil {
		return nil, err
	}

	nextHop := remoteIP
	if !pcapAddressContainsIPv4(address, remoteIP) {
		nextHop, err = synRouteNextHopIPv4(remoteIP)
		if err != nil {
			return nil, err
		}
		nextHop = nextHop.To4()
		if nextHop == nil {
			return nil, errSYNDiscoveryUnavailable
		}
	}

	dstMAC, err := resolveSYNLayer2MAC(device.Name, srcIP, srcMAC, nextHop, s.timeout)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(device.Name, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	route := &synLayer2Route{
		handle: handle,
		srcIP:  srcIP,
		srcMAC: srcMAC,
		dstMAC: dstMAC,
	}

	s.mu.Lock()
	if existing := s.routes[key]; existing != nil {
		s.mu.Unlock()
		handle.Close()
		return existing, nil
	}
	s.routes[key] = route
	s.mu.Unlock()
	return route, nil
}

func synRouteNextHopIPv4(remoteIP net.IP) (net.IP, error) {
	remoteIP = remoteIP.To4()
	if remoteIP == nil {
		return nil, errSYNDiscoveryUnavailable
	}

	router, err := netroute.New()
	if err == nil {
		_, routeGateway, _, routeErr := router.Route(remoteIP)
		if routeErr == nil {
			if routeGateway == nil || routeGateway.To4() == nil || routeGateway.IsUnspecified() {
				return remoteIP, nil
			}
			return routeGateway.To4(), nil
		}
	}

	defaultGateway, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	defaultGateway = defaultGateway.To4()
	if defaultGateway == nil {
		return nil, errSYNDiscoveryUnavailable
	}
	return defaultGateway, nil
}

func (s *synLayer2PacketSender) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, route := range s.routes {
		route.handle.Close()
		delete(s.routes, key)
	}
}

func synPCAPDeviceForIPv4(ip net.IP) (pcap.Interface, pcap.InterfaceAddress, error) {
	ip = ip.To4()
	if ip == nil {
		return pcap.Interface{}, pcap.InterfaceAddress{}, errSYNDiscoveryUnavailable
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, pcap.InterfaceAddress{}, err
	}
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.To4().Equal(ip) {
				return device, address, nil
			}
		}
	}
	return pcap.Interface{}, pcap.InterfaceAddress{}, fmt.Errorf("%w: no pcap device for %s", errSYNDiscoveryUnavailable, ip.String())
}

func localHardwareAddrForIPv4(ip net.IP) (net.HardwareAddr, error) {
	ip = ip.To4()
	if ip == nil {
		return nil, errSYNDiscoveryUnavailable
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4().Equal(ip) && len(iface.HardwareAddr) > 0 {
				return iface.HardwareAddr, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no local mac for %s", errSYNDiscoveryUnavailable, ip.String())
}

func pcapAddressContainsIPv4(address pcap.InterfaceAddress, ip net.IP) bool {
	base := address.IP.To4()
	ip = ip.To4()
	if base == nil || ip == nil || address.Netmask == nil {
		return false
	}
	return base.Mask(address.Netmask).Equal(ip.Mask(address.Netmask))
}

func resolveSYNLayer2MAC(deviceName string, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	srcIP = srcIP.To4()
	targetIP = targetIP.To4()
	if srcIP == nil || targetIP == nil || len(srcMAC) == 0 {
		return nil, errSYNDiscoveryUnavailable
	}
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}

	handle, err := pcap.OpenLive(deviceName, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}

	request, err := buildARPRequest(srcIP, srcMAC, targetIP)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	nextSend := time.Time{}
	for time.Now().Before(deadline) {
		if time.Now().After(nextSend) {
			if err := handle.WritePacketData(request); err != nil {
				return nil, err
			}
			nextSend = time.Now().Add(200 * time.Millisecond)
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, ok := arpLayer.(*layers.ARP)
		if !ok || arp.Operation != layers.ARPReply {
			continue
		}
		if !net.IP(arp.SourceProtAddress).To4().Equal(targetIP) {
			continue
		}
		if len(arp.SourceHwAddress) == 0 {
			continue
		}
		return net.HardwareAddr(append([]byte(nil), arp.SourceHwAddress...)), nil
	}
	return nil, fmt.Errorf("%w: timeout resolving mac for %s", errSYNDiscoveryUnavailable, targetIP.String())
}

func buildARPRequest(srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		return nil, err
	}
	return append([]byte(nil), buf.Bytes()...), nil
}
