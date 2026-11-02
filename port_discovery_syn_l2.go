package gonmap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type synWriteHandle interface {
	WritePacketData([]byte) error
	Close()
}

// A failed native handle can be retired before scanner shutdown. The wrapper
// preserves exactly-once closure when it is also visited by final cleanup.
type synOwnedWriteHandle struct {
	synWriteHandle
	once sync.Once
}

func (h *synOwnedWriteHandle) Close() { h.once.Do(h.synWriteHandle.Close) }

type synSharedHandle struct {
	mu             sync.Mutex
	handle         synWriteHandle
	device         string
	reopenAttempts int
	lastError      error
}
type synL2Interface struct {
	name    string
	mac     net.HardwareAddr
	network *net.IPNet
}
type synL2Dependencies struct {
	source  func(context.Context, net.IP, time.Duration) (net.IP, error)
	device  func(net.IP) (synL2Interface, error)
	nextHop func(context.Context, net.IP) (net.IP, error)
	resolve func(context.Context, string, net.IP, net.HardwareAddr, net.IP, time.Duration) (net.HardwareAddr, error)
	open    func(string) (synWriteHandle, error)
}
type synCacheEntry[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// Coalesce concurrent requests. Only the owner performs bounded real retries.
// A terminal failure is shared for this scanner/round, never a first-failure
// negative cache. Cancellation is evicted; waiters can independently cancel.
func synCached[T any](ctx context.Context, mu *sync.Mutex, cache map[string]*synCacheEntry[T], key string, onHit func(), work func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	mu.Lock()
	if entry := cache[key]; entry != nil {
		if onHit != nil {
			onHit()
		}
		mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-entry.done:
			return entry.value, entry.err
		}
	}
	entry := &synCacheEntry[T]{done: make(chan struct{})}
	cache[key] = entry
	mu.Unlock()
	entry.value, entry.err = work()
	mu.Lock()
	if ctx.Err() != nil {
		entry.err = ctx.Err()
		delete(cache, key)
	}
	close(entry.done)
	mu.Unlock()
	return entry.value, entry.err
}
func synRetry[T any](ctx context.Context, work func() (T, error)) (T, error) {
	var value T
	var err error
	for attempt := 0; attempt < maxSYNSendFailuresPerHost; attempt++ {
		if err = ctx.Err(); err != nil {
			return value, err
		}
		value, err = work()
		if ctx.Err() != nil {
			return value, ctx.Err()
		}
		if err == nil {
			return value, nil
		}
	}
	return value, err
}

type synLayer2PacketSender struct {
	timeout time.Duration
	opts    gopacket.SerializeOptions
	deps    synL2Dependencies
	// close waits for preparation, writes and RST cleanup; no resource is closed
	// while still in use. Native operations must return before close can finish.
	life   sync.RWMutex
	closed bool

	mu        sync.Mutex
	routes    map[string]*synLayer2Route
	devices   map[string]*synCacheEntry[synL2Interface]
	neighbors map[string]*synCacheEntry[net.HardwareAddr]
	handles   map[string]*synCacheEntry[*synSharedHandle]

	sourceDuration, routeDuration, writeDuration     time.Duration
	neighborAttempts, neighborCacheHits, sendHandles int

	owned []synWriteHandle
}
type synLayer2Route struct {
	handle         *synSharedHandle
	srcIP          net.IP
	srcMAC, dstMAC net.HardwareAddr
}

func newSYNLayer2Sender(timeout time.Duration, deps synL2Dependencies) *synLayer2PacketSender {
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	return &synLayer2PacketSender{
		timeout:   timeout,
		deps:      deps,
		opts:      gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		routes:    make(map[string]*synLayer2Route),
		devices:   make(map[string]*synCacheEntry[synL2Interface]),
		neighbors: make(map[string]*synCacheEntry[net.HardwareAddr]),
		handles:   make(map[string]*synCacheEntry[*synSharedHandle]),
	}
}

func (s *synLayer2PacketSender) prepare(ctx context.Context, remote net.IP) (net.IP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return nil, errSYNDiscoveryUnavailable
	}
	started := time.Now()
	defer func() { s.mu.Lock(); s.routeDuration += time.Since(started); s.mu.Unlock() }()
	s.mu.Lock()
	existing := s.routes[remote.String()]
	s.mu.Unlock()
	if existing != nil {
		return existing.srcIP, ctx.Err()
	}
	lookupStarted := time.Now()
	src, err := synRetry(ctx, func() (net.IP, error) { return s.deps.source(ctx, remote, s.timeout) })
	s.mu.Lock()
	s.sourceDuration += time.Since(lookupStarted)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("SYN source address: %w", err)
	}
	if src.To4() == nil {
		return nil, errSYNDiscoveryUnavailable
	}
	device, err := synCached(ctx, &s.mu, s.devices, src.String(), nil, func() (synL2Interface, error) {
		return synRetry(ctx, func() (synL2Interface, error) { return s.deps.device(src) })
	})
	if err != nil {
		return nil, fmt.Errorf("SYN interface: %w", err)
	}
	next := remote
	if device.network == nil || !device.network.Contains(remote) {
		next, err = synRetry(ctx, func() (net.IP, error) { return s.deps.nextHop(ctx, remote) })
		if err != nil {
			return nil, fmt.Errorf("SYN next hop: %w", err)
		}
	}
	if next.To4() == nil {
		return nil, errSYNDiscoveryUnavailable
	}
	key := device.name + "\x00" + src.String() + "\x00" + device.mac.String() + "\x00" + next.String()
	mac, err := synCached(ctx, &s.mu, s.neighbors, key, func() { s.neighborCacheHits++ }, func() (net.HardwareAddr, error) {
		return synRetry(ctx, func() (net.HardwareAddr, error) {
			s.mu.Lock()
			s.neighborAttempts++
			s.mu.Unlock()
			mac, err := s.deps.resolve(ctx, device.name, src, device.mac, next, s.timeout)
			if err == nil && len(mac) != 6 {
				err = fmt.Errorf("invalid next-hop MAC for %s", next)
			}
			return mac, err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("SYN neighbor %s on %s: %w", next, device.name, err)
	}
	handle, err := synCached(ctx, &s.mu, s.handles, device.name, nil, func() (*synSharedHandle, error) {
		return synRetry(ctx, func() (*synSharedHandle, error) {
			h, err := s.deps.open(device.name)
			if err != nil {
				if h != nil {
					h.Close()
				}
				return nil, err
			}
			if h == nil {
				return nil, fmt.Errorf("nil SYN handle for %s", device.name)
			}
			// Publish ownership even if cancellation arrives as OpenLive returns. The
			// enclosing cache retains resources for close.
			owned := s.ownHandle(h)
			return &synSharedHandle{handle: owned, device: device.name}, nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("SYN open interface %s: %w", device.name, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	route := &synLayer2Route{handle: handle, srcIP: src, srcMAC: device.mac, dstMAC: mac}
	s.mu.Lock()
	s.routes[remote.String()] = route
	s.mu.Unlock()
	return src, nil
}

func (s *synLayer2PacketSender) sendTCP(ctx context.Context, remoteIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16) (net.IP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return nil, errSYNDiscoveryUnavailable
	}
	s.mu.Lock()
	route := s.routes[remoteIP.String()]
	s.mu.Unlock()
	if route == nil {
		return nil, fmt.Errorf("SYN route not prepared for %s", remoteIP)
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

	route.handle.mu.Lock()
	defer route.handle.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	shared := route.handle
	if shared.handle == nil {
		// All routes retain this shared object. Repair it in place, under the
		// same write lock, and bound recovery across the whole interface/round.
		if shared.reopenAttempts >= maxSYNSendFailuresPerHost {
			return nil, fmt.Errorf("SYN interface %s reopen budget exhausted: %w", shared.device, shared.lastError)
		}
		shared.reopenAttempts++
		handle, err := s.deps.open(shared.device)
		if err != nil {
			if handle != nil {
				handle.Close()
			}
			shared.lastError = err
			return nil, fmt.Errorf("SYN reopen interface %s: %w", shared.device, err)
		}
		if handle == nil {
			shared.lastError = fmt.Errorf("nil SYN handle for %s", shared.device)
			return nil, shared.lastError
		}
		shared.handle = s.ownHandle(handle)
		// Even if cancellation arrived during OpenLive, final cleanup owns it.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	started := time.Now()
	err := shared.handle.WritePacketData(buf.Bytes())
	s.mu.Lock()
	s.writeDuration += time.Since(started)
	s.mu.Unlock()
	if err != nil {
		shared.lastError = err
		shared.handle.Close()
		shared.handle = nil
		return nil, fmt.Errorf("SYN packet write: %w", err)
	}
	return route.srcIP, nil
}

// Caller holds a life read lock, so close cannot traverse owned concurrently.
func (s *synLayer2PacketSender) ownHandle(handle synWriteHandle) synWriteHandle {
	owned := &synOwnedWriteHandle{synWriteHandle: handle}
	s.mu.Lock()
	s.sendHandles++
	s.owned = append(s.owned, owned)
	s.mu.Unlock()
	return owned
}

func (s *synLayer2PacketSender) close() {
	s.life.Lock()
	defer s.life.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, handle := range s.owned {
		handle.Close()
	}
	s.owned = nil
}
func (s *synLayer2PacketSender) timings() (time.Duration, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routeDuration, s.writeDuration
}
func (s *synLayer2PacketSender) preparationDiagnostics() (time.Duration, int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sourceDuration, s.neighborAttempts, s.neighborCacheHits, s.sendHandles
}

// Cache a default-gateway fallback only after the owner has made bounded real
// attempts. sync.Once would permanently cache the first transient error.
func newSYNGatewayLookup(discover func() (net.IP, error)) func(context.Context) (net.IP, error) {
	var mu sync.Mutex
	cache := make(map[string]*synCacheEntry[net.IP])
	return func(ctx context.Context) (net.IP, error) {
		return synCached(ctx, &mu, cache, "default", nil, func() (net.IP, error) {
			return synRetry(ctx, func() (net.IP, error) {
				ip, err := discover()
				if err == nil && (ip.To4() == nil || ip.IsUnspecified()) {
					err = fmt.Errorf("invalid SYN default gateway: %s", ip)
				}
				return ip, err
			})
		})
	}
}

// Separate ARP capture handles still see each other's replies. Only accept an
// Ethernet/IPv4 reply addressed to this exact source IP and MAC before caching.
func synARPReplyMAC(data []byte, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP) net.HardwareAddr {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	layer := packet.Layer(layers.LayerTypeARP)
	arp, ok := layer.(*layers.ARP)
	if !ok || arp.Operation != layers.ARPReply || arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 || arp.HwAddressSize != 6 || arp.ProtAddressSize != 4 {
		return nil
	}
	if len(arp.SourceHwAddress) != 6 || arp.SourceHwAddress[0]&1 != 0 || bytes.Equal(arp.SourceHwAddress, make([]byte, 6)) ||
		!net.IP(arp.SourceProtAddress).Equal(targetIP) || !net.IP(arp.DstProtAddress).Equal(srcIP) || !bytes.Equal(arp.DstHwAddress, srcMAC) {
		return nil
	}
	return append(net.HardwareAddr(nil), arp.SourceHwAddress...)
}
