//go:build windows

package gonmap

import (
	"context"
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

func newSYNLayer2PacketSender(timeout time.Duration) (synPacketSender, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	router, routeErr := netroute.New()
	var routeMu sync.Mutex
	fallbackGateway := newSYNGatewayLookup(gateway.DiscoverGateway)
	return newSYNLayer2Sender(timeout, synL2Dependencies{
		source: localIPv4ForRemote,
		device: func(src net.IP) (synL2Interface, error) {
			for _, device := range devices {
				for _, addr := range device.Addresses {
					if addr.IP.To4() != nil && addr.IP.Equal(src) {
						mac, err := localHardwareAddrForIPv4(src)
						if err != nil {
							return synL2Interface{}, err
						}
						return synL2Interface{name: device.Name, mac: mac, network: &net.IPNet{IP: addr.IP, Mask: addr.Netmask}}, nil
					}
				}
			}
			return synL2Interface{}, fmt.Errorf("%w: no pcap device for %s", errSYNDiscoveryUnavailable, src)
		},
		nextHop: func(ctx context.Context, remote net.IP) (net.IP, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Route() uses the per-round routing snapshot. Do not hold this
			// lock while a fallback gateway lookup may block other workers.
			if routeErr == nil {
				routeMu.Lock()
				_, hop, _, err := router.Route(remote)
				routeMu.Unlock()
				if err == nil {
					if hop == nil || hop.IsUnspecified() {
						return remote, nil
					}
					return hop.To4(), nil
				}
			}
			return fallbackGateway(ctx)
		},
		resolve: resolveSYNLayer2MAC,
		open: func(name string) (synWriteHandle, error) {
			h, err := pcap.OpenLive(name, 65535, false, 100*time.Millisecond)
			if err != nil {
				return nil, err
			}
			return h, nil
		},
	}), nil
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

func resolveSYNLayer2MAC(ctx context.Context, deviceName string, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(nextSend) {
			if err := handle.WritePacketData(request); err != nil {
				return nil, err
			}
			nextSend = time.Now().Add(200 * time.Millisecond)
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return nil, fmt.Errorf("SYN ARP read on %s: %w", deviceName, err)
		}

		if mac := synARPReplyMAC(data, srcIP, srcMAC, targetIP); mac != nil {
			return mac, nil
		}
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
