package gonmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type testSYNHandle struct {
	writes atomic.Int32
	closes atomic.Int32
	write  func([]byte) error
}

func (h *testSYNHandle) WritePacketData(b []byte) error {
	h.writes.Add(1)
	if h.write != nil {
		return h.write(b)
	}
	return nil
}
func (h *testSYNHandle) Close() { h.closes.Add(1) }
func testSYNDependencies(h *testSYNHandle) synL2Dependencies {
	_, network, _ := net.ParseCIDR("192.0.2.0/24")
	return synL2Dependencies{
		source: func(context.Context, net.IP, time.Duration) (net.IP, error) {
			return net.ParseIP("192.0.2.100").To4(), nil
		},
		device: func(net.IP) (synL2Interface, error) {
			return synL2Interface{name: "nic0", mac: net.HardwareAddr{2, 0, 0, 0, 0, 1}, network: network}, nil
		},
		nextHop: func(context.Context, net.IP) (net.IP, error) { return net.ParseIP("192.0.2.254").To4(), nil },
		resolve: func(context.Context, string, net.IP, net.HardwareAddr, net.IP, time.Duration) (net.HardwareAddr, error) {
			return net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
		},
		open: func(string) (synWriteHandle, error) { return h, nil },
	}
}
func awaitSYN[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SYN test event")
		var zero T
		return zero
	}
}

// A real scanner and the shared L2 sender are used, with only OS I/O injected.
// The first host cannot finish ARP until the second host has actually sent SYN.
func TestSYNReadyHostSendsWhileEarlierNeighborIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := make(chan struct{})
	fastSent := make(chan string, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	handle := &testSYNHandle{write: func(b []byte) error {
		packet := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip.DstIP.String() == "192.0.2.2" {
			select {
			case fastSent <- ip.DstIP.String():
			default:
			}
		}
		return nil
	}}
	deps := testSYNDependencies(handle)
	var sourceCalls atomic.Int32
	source := deps.source
	deps.source = func(ctx context.Context, ip net.IP, d time.Duration) (net.IP, error) {
		sourceCalls.Add(1)
		return source(ctx, ip, d)
	}
	resolve := deps.resolve
	deps.resolve = func(ctx context.Context, dev string, src net.IP, mac net.HardwareAddr, next net.IP, d time.Duration) (net.HardwareAddr, error) {
		if next.String() == "192.0.2.1" {
			close(blocked)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			select {
			case <-blocked:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return resolve(ctx, dev, src, mac, next, d)
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer func() { cancel(); unblock(); sender.close() }()
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	scanner.resolveSource = func(context.Context, net.IP, time.Duration) (net.IP, error) {
		return nil, errors.New("source lookup leaked into send loop")
	}
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	done := make(chan error, 1)
	go func() {
		done <- scanner.scan(ctx, append(testSYNTasks("192.0.2.1", 320), testSYNTasks("192.0.2.2", 320)...))
	}()
	awaitSYN(t, fastSent)
	unblock()
	if err := awaitSYN(t, done); err != nil {
		t.Fatal(err)
	}
	if sourceCalls.Load() != 2 || handle.writes.Load() != 640 || final.PreparedHosts != 2 || final.NeighborAttempts != 2 || final.SendHandles != 1 || final.Attempted != 640 || final.PrepareFailures != 0 {
		t.Fatalf("sources=%d writes=%d diagnostic=%+v", sourceCalls.Load(), handle.writes.Load(), final)
	}
}

func TestSYNNeighborRequestsCoalesceAndRetryRealOperations(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminalFailure=%t", fail), func(t *testing.T) {
			handle := &testSYNHandle{}
			deps := testSYNDependencies(handle)
			var attempts, opens, devices atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			deps.resolve = func(ctx context.Context, _ string, _ net.IP, _ net.HardwareAddr, _ net.IP, _ time.Duration) (net.HardwareAddr, error) {
				n := attempts.Add(1)
				if n == 1 {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				if fail || n < 3 {
					return nil, errors.New("ARP timeout")
				}
				return net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
			}
			device := deps.device
			deps.device = func(ip net.IP) (synL2Interface, error) { devices.Add(1); return device(ip) }
			deps.open = func(string) (synWriteHandle, error) { opens.Add(1); return handle, nil }
			sender := newSYNLayer2Sender(time.Second, deps)
			defer func() { unblock(); sender.close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			const hosts = 32
			ready := make(chan error, hosts)
			for i := 1; i <= hosts; i++ {
				go func(i int) { _, err := sender.prepare(ctx, net.IPv4(198, 51, 100, byte(i))); ready <- err }(i)
			}
			awaitSYN(t, entered)
			unblock()
			for i := 0; i < hosts; i++ {
				err := awaitSYN(t, ready)
				if (err != nil) != fail {
					t.Fatalf("prepare=%v fail=%t", err, fail)
				}
			}
			if attempts.Load() != 3 || devices.Load() != 1 {
				t.Fatalf("attempts=%d devices=%d", attempts.Load(), devices.Load())
			}
			if fail {
				if opens.Load() != 0 {
					t.Fatal("opened send handle for unresolved route")
				}
			} else {
				if opens.Load() != 1 {
					t.Fatalf("opens=%d", opens.Load())
				}
				// SYN and RST reuse the same prepared route; neither performs another ARP.
				for _, flags := range []uint8{tcpFlagSYN, tcpFlagRST | tcpFlagACK} {
					if _, err := sender.sendTCP(ctx, net.IPv4(198, 51, 100, 1), 40000, 80, 1, 0, flags, 1024); err != nil {
						t.Fatal(err)
					}
				}
				if attempts.Load() != 3 || handle.writes.Load() != 2 {
					t.Fatal("send performed resolution")
				}
			}
			sender.close()
			sender.close()
			if handle.closes.Load() != opens.Load() {
				t.Fatalf("opens=%d closes=%d", opens.Load(), handle.closes.Load())
			}
		})
	}
}

func TestSYNPrepareFailureSkipsPortsButKeepsOtherHosts(t *testing.T) {
	handle := &testSYNHandle{}
	deps := testSYNDependencies(handle)
	var failedResolves atomic.Int32
	resolve := deps.resolve
	deps.resolve = func(ctx context.Context, dev string, src net.IP, mac net.HardwareAddr, next net.IP, d time.Duration) (net.HardwareAddr, error) {
		if next.String() == "192.0.2.1" {
			failedResolves.Add(1)
			return nil, errors.New("ARP timeout")
		}
		return resolve(ctx, dev, src, mac, next, d)
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	var final SYNDiscoveryDiagnostics
	unreachable := 0
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	scanner.onHostUnreachable = func(host string, err error) {
		if host != "192.0.2.1" || err == nil {
			t.Fatalf("host=%s err=%v", host, err)
		}
		unreachable++
	}
	if err := scanner.scan(context.Background(), append(testSYNTasks("192.0.2.1", 320), testSYNTasks("192.0.2.2", 2)...)); err != nil {
		t.Fatal(err)
	}
	if failedResolves.Load() != 3 || unreachable != 1 || final.PrepareFailures != 1 || final.PreparedHosts != 1 || final.Failed != 0 || final.Sent != 2 || final.Skipped != 320 || final.Attempted != 322 || final.NeighborAttempts != 4 {
		t.Fatalf("attempts=%d unreachable=%d diagnostic=%+v", failedResolves.Load(), unreachable, final)
	}
}

func TestSYNCacheSeparatesInterfacesWithSameNextHop(t *testing.T) {
	handles := map[string]*testSYNHandle{"nic1": {}, "nic2": {}}
	deps := testSYNDependencies(nil)
	deps.source = func(_ context.Context, ip net.IP, _ time.Duration) (net.IP, error) {
		return net.IPv4(192, 0, 2, ip.To4()[3]), nil
	}
	deps.device = func(ip net.IP) (synL2Interface, error) {
		n := ip.To4()[3]
		return synL2Interface{name: fmt.Sprintf("nic%d", n), mac: net.HardwareAddr{2, 0, 0, 0, 0, n}}, nil
	}
	var resolves atomic.Int32
	deps.resolve = func(_ context.Context, dev string, src net.IP, _ net.HardwareAddr, _ net.IP, _ time.Duration) (net.HardwareAddr, error) {
		resolves.Add(1)
		return net.HardwareAddr{2, 0, 0, 0, 1, src.To4()[3]}, nil
	}
	deps.open = func(dev string) (synWriteHandle, error) { return handles[dev], nil }
	for name, h := range handles {
		name := name
		h.write = func(b []byte) error {
			p := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
			eth := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if fmt.Sprintf("nic%d", ip.SrcIP.To4()[3]) != name || eth.DstMAC[5] != ip.SrcIP.To4()[3] {
				return errors.New("route crossed interfaces")
			}
			return nil
		}
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	for i := 1; i <= 2; i++ {
		ip := net.IPv4(198, 51, 100, byte(i))
		if _, err := sender.prepare(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
		if _, err := sender.sendTCP(context.Background(), ip, 40000, 80, 1, 0, tcpFlagSYN, 1024); err != nil {
			t.Fatal(err)
		}
	}
	if resolves.Load() != 2 {
		t.Fatalf("resolves=%d", resolves.Load())
	}
	sender.close()
	for name, h := range handles {
		if h.writes.Load() != 1 || h.closes.Load() != 1 {
			t.Fatalf("%s writes=%d closes=%d", name, h.writes.Load(), h.closes.Load())
		}
	}
}

func TestSYNCancelDoesNotCacheFailureOrLeakOpenedHandle(t *testing.T) {
	handle := &testSYNHandle{}
	deps := testSYNDependencies(handle)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	deps.open = func(string) (synWriteHandle, error) {
		if calls.Add(1) == 1 {
			cancel()
		}
		return handle, nil
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	ip := net.IPv4(198, 51, 100, 1)
	if _, err := sender.prepare(ctx, ip); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// A distinct second handle proves the canceled entry is evicted and both
	// resources remain owned until close, even though the first route was not published.
	second := &testSYNHandle{}
	sender.deps.open = func(string) (synWriteHandle, error) { calls.Add(1); return second, nil }
	if _, err := sender.prepare(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	sender.close()
	sender.close()
	if calls.Load() != 2 || handle.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatalf("opens=%d closes=%d/%d", calls.Load(), handle.closes.Load(), second.closes.Load())
	}
}

func TestSYNSendRequiresPreparedRouteAndCloseWaitsForWriter(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	handle := &testSYNHandle{write: func([]byte) error { close(entered); <-release; return nil }}
	sender := newSYNLayer2Sender(time.Second, testSYNDependencies(handle))
	defer func() { unblock(); sender.close() }()
	ip := net.IPv4(192, 0, 2, 1)
	send := func() error {
		_, err := sender.sendTCP(context.Background(), ip, 40000, 80, 1, 0, tcpFlagSYN, 1024)
		return err
	}
	if err := send(); err == nil {
		t.Fatal("send must require prepared route")
	}
	if _, err := sender.prepare(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- send() }()
	awaitSYN(t, entered)
	closed := make(chan struct{})
	go func() { sender.close(); close(closed) }()
	if handle.closes.Load() != 0 {
		t.Fatal("closed active writer")
	}
	unblock()
	if err := awaitSYN(t, sent); err != nil {
		t.Fatal(err)
	}
	awaitSYN(t, closed)
	if handle.closes.Load() != 1 {
		t.Fatal("handle not closed exactly once")
	}
	if err := send(); err == nil {
		t.Fatal("send after close succeeded")
	}
}

type testSYNPreparer struct {
	*boundedSYNSender
	prepareFn func(context.Context, net.IP) (net.IP, error)
}

func (s *testSYNPreparer) prepare(ctx context.Context, ip net.IP) (net.IP, error) {
	return s.prepareFn(ctx, ip)
}
func TestSYNPreparationBoundedAndCancellationWaitsForWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, synPrepareWorkers*2)
	sawCancel := make(chan struct{}, synPrepareWorkers)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var active, peak atomic.Int32
	sender := &testSYNPreparer{boundedSYNSender: &boundedSYNSender{calls: make(map[string][]uint16)}}
	sender.prepareFn = func(ctx context.Context, _ net.IP) (net.IP, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-ctx.Done()
		sawCancel <- struct{}{}
		<-release
		return nil, ctx.Err()
	}
	tasks := []synScanTask{}
	for i := 1; i <= 100; i++ {
		tasks = append(tasks, testSYNTasks(fmt.Sprintf("192.0.2.%d", i), 2)...)
	}
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	scanner.onHostUnreachable = func(string, error) { t.Error("cancellation reported as unreachable") }
	done := make(chan error, 1)
	go func() { done <- scanner.scan(ctx, tasks) }()
	for i := 0; i < synPrepareWorkers; i++ {
		awaitSYN(t, started)
	}
	if peak.Load() != synPrepareWorkers {
		t.Fatalf("peak=%d", peak.Load())
	}
	cancel()
	for i := 0; i < synPrepareWorkers; i++ {
		awaitSYN(t, sawCancel)
	}
	select {
	case err := <-done:
		t.Fatalf("scan acknowledged before workers exited: %v", err)
	default:
	}
	unblock()
	if err := awaitSYN(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if active.Load() != 0 || peak.Load() > synPrepareWorkers || final.Attempted != 0 || final.PrepareFailures != 0 || final.UnreachableHosts != 0 || !final.Done {
		t.Fatalf("active=%d peak=%d diagnostic=%+v", active.Load(), peak.Load(), final)
	}
}

func TestSYNAllHostsBehindFailedGatewayDiagnosed(t *testing.T) {
	handle := &testSYNHandle{}
	deps := testSYNDependencies(handle)
	deps.resolve = func(context.Context, string, net.IP, net.HardwareAddr, net.IP, time.Duration) (net.HardwareAddr, error) {
		return nil, errors.New("gateway ARP timeout")
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	tasks := []synScanTask{}
	for i := 1; i <= 32; i++ {
		tasks = append(tasks, testSYNTasks(fmt.Sprintf("198.51.100.%d", i), 320)...)
	}
	if err := scanner.scan(context.Background(), tasks); err == nil {
		t.Fatal("entire preparation failure must propagate")
	}
	if final.NeighborAttempts != 3 || final.NeighborCacheHits != 31 || final.PrepareFailures != 32 || final.UnreachableHosts != 32 || final.Skipped != 10240 || final.Sent != 0 || final.Failed != 0 || final.SendHandles != 0 || final.Error == "" || !final.Done {
		t.Fatalf("diagnostic=%+v", final)
	}
}

func TestSYNPreparationSourceRetriesAndCancelledNeighborIsEvicted(t *testing.T) {
	handle := &testSYNHandle{}
	deps := testSYNDependencies(handle)
	source := deps.source
	var sources atomic.Int32
	deps.source = func(ctx context.Context, ip net.IP, d time.Duration) (net.IP, error) {
		if sources.Add(1) <= 2 {
			return nil, errors.New("temporary source lookup failure")
		}
		return source(ctx, ip, d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var resolves atomic.Int32
	deps.resolve = func(context.Context, string, net.IP, net.HardwareAddr, net.IP, time.Duration) (net.HardwareAddr, error) {
		if resolves.Add(1) == 1 {
			cancel()
			return nil, context.Canceled
		}
		return net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	if _, err := sender.prepare(ctx, net.IPv4(198, 51, 100, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if sources.Load() != 3 || resolves.Load() != 1 {
		t.Fatalf("sources=%d resolves=%d", sources.Load(), resolves.Load())
	}
	if _, err := sender.prepare(context.Background(), net.IPv4(198, 51, 100, 2)); err != nil {
		t.Fatal(err)
	}
	if resolves.Load() != 2 {
		t.Fatal("canceled neighbor poisoned shared cache")
	}
}

func TestSYNGatewayFallbackRetriesBeforeSharingFailure(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
			var calls atomic.Int32
			lookup := newSYNGatewayLookup(func() (net.IP, error) {
				n := calls.Add(1)
				if terminal || n < 3 {
					return nil, errors.New("temporary gateway discovery failure")
				}
				return net.IPv4(192, 0, 2, 254), nil
			})
			done := make(chan error, 32)
			for i := 0; i < 32; i++ {
				go func() { _, err := lookup(context.Background()); done <- err }()
			}
			for i := 0; i < 32; i++ {
				if err := awaitSYN(t, done); (err != nil) != terminal {
					t.Fatalf("terminal=%v err=%v", terminal, err)
				}
			}
			if calls.Load() != 3 {
				t.Fatalf("real gateway calls=%d, want 3", calls.Load())
			}
		})
	}
}

func TestSYNARPRepliesMustMatchFullResolutionRequest(t *testing.T) {
	src := net.IPv4(192, 0, 2, 100)
	next := net.IPv4(192, 0, 2, 254)
	local := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	remote := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	for _, tc := range []struct {
		name   string
		mutate func(*layers.ARP)
		valid  bool
	}{
		{"valid", func(*layers.ARP) {}, true},
		{"other source IP", func(a *layers.ARP) { a.DstProtAddress = net.IPv4(192, 0, 2, 101).To4() }, false},
		{"other source MAC", func(a *layers.ARP) { a.DstHwAddress = []byte{2, 0, 0, 0, 0, 9} }, false},
		{"other neighbor", func(a *layers.ARP) { a.SourceProtAddress = net.IPv4(192, 0, 2, 253).To4() }, false},
		{"request", func(a *layers.ARP) { a.Operation = layers.ARPRequest }, false},
		{"multicast MAC", func(a *layers.ARP) { a.SourceHwAddress = []byte{1, 0, 0, 0, 0, 2} }, false},
		{"zero MAC", func(a *layers.ARP) { a.SourceHwAddress = make([]byte, 6) }, false},
		{"other protocol", func(a *layers.ARP) { a.Protocol = layers.EthernetTypeIPv6 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, Operation: layers.ARPReply, SourceHwAddress: remote, SourceProtAddress: next.To4(), DstHwAddress: local, DstProtAddress: src.To4()}
			tc.mutate(arp)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &layers.Ethernet{SrcMAC: remote, DstMAC: local, EthernetType: layers.EthernetTypeARP}, arp); err != nil {
				t.Fatal(err)
			}
			got := synARPReplyMAC(buf.Bytes(), src, local, next)
			if (got != nil) != tc.valid {
				t.Fatalf("accepted=%v want=%v", got, tc.valid)
			}
			if tc.valid {
				for i := range buf.Bytes() {
					buf.Bytes()[i] = 0
				}
				if got.String() != remote.String() {
					t.Fatal("MAC aliases capture buffer")
				}
			}
		})
	}
	if synARPReplyMAC([]byte{1, 2}, src, local, next) != nil {
		t.Fatal("accepted truncated packet")
	}
}

func TestSYNReadyQueueCancelsWithFullResultBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prepared := make(chan struct{}, 100)
	sender := &testSYNPreparer{boundedSYNSender: &boundedSYNSender{calls: make(map[string][]uint16)}, prepareFn: func(context.Context, net.IP) (net.IP, error) {
		prepared <- struct{}{}
		return net.IPv4(192, 0, 2, 100), nil
	}}
	tasks := []synScanTask{}
	for i := 1; i <= 100; i++ {
		tasks = append(tasks, testSYNTasks(fmt.Sprintf("192.0.2.%d", i), 1)...)
	}
	queue := newSYNReadyTasks(ctx, tasks, sender)
	defer queue.stop()
	// 16 buffered results plus 16 workers waiting to publish, with no consumer.
	for i := 0; i < 2*synPrepareWorkers; i++ {
		awaitSYN(t, prepared)
	}
	stopped := make(chan struct{})
	go func() { queue.stop(); close(stopped) }()
	awaitSYN(t, stopped)
}

func TestSYNCacheWaiterCanCancelWithoutEvictingOwner(t *testing.T) {
	var mu sync.Mutex
	cache := make(map[string]*synCacheEntry[int])
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	work := func() (int, error) { calls.Add(1); close(entered); <-release; return 42, nil }
	ownerDone := make(chan error, 1)
	go func() { _, err := synCached(context.Background(), &mu, cache, "key", nil, work); ownerDone <- err }()
	awaitSYN(t, entered)
	waiterCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := make(chan struct{})
	waiterDone := make(chan error, 1)
	go func() {
		_, err := synCached(waiterCtx, &mu, cache, "key", func() { close(waiting) }, work)
		waiterDone <- err
	}()
	awaitSYN(t, waiting)
	cancel()
	if err := awaitSYN(t, waiterDone); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unblock()
	if err := awaitSYN(t, ownerDone); err != nil {
		t.Fatal(err)
	}
	value, err := synCached(context.Background(), &mu, cache, "key", nil, work)
	if err != nil || value != 42 || calls.Load() != 1 {
		t.Fatalf("value=%d err=%v calls=%d", value, err, calls.Load())
	}
}

func TestSYNCancellationDuringResultDrainWaitsAndPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := &boundedSYNSender{calls: make(map[string][]uint16)}
	scanner := testBoundedSYNScanner(sender)
	scanner.openEvents = []OpenPort{{Host: "192.0.2.1", Port: 80}}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	scanDone := make(chan struct{})
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) {
		if d.Done {
			close(scanDone)
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- scanner.scanWithEvents(ctx, testSYNTasks("192.0.2.1", 1), func(OpenPort) { close(entered); <-release })
	}()
	awaitSYN(t, entered)
	awaitSYN(t, scanDone)
	// The send/receive phase finished successfully, but a callback still owns work.
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned before callback exit: %v", err)
	default:
	}
	unblock()
	if err := awaitSYN(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation swallowed: %v", err)
	}
}

func TestSYNSharedHandleSerializesConcurrentSYNAndRST(t *testing.T) {
	var active atomic.Int32
	handle := &testSYNHandle{write: func([]byte) error {
		n := active.Add(1)
		defer active.Add(-1)
		runtime.Gosched()
		if n != 1 {
			return errors.New("concurrent write on shared pcap handle")
		}
		return nil
	}}
	sender := newSYNLayer2Sender(time.Second, testSYNDependencies(handle))
	defer sender.close()
	ip := net.IPv4(192, 0, 2, 1)
	if _, err := sender.prepare(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func(i int) {
			flags := uint8(tcpFlagSYN)
			if i%2 == 1 {
				flags = tcpFlagRST | tcpFlagACK
			}
			_, err := sender.sendTCP(context.Background(), ip, 40000, 80, 1, 1, flags, 1024)
			done <- err
		}(i)
	}
	for i := 0; i < 64; i++ {
		if err := awaitSYN(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if handle.writes.Load() != 64 {
		t.Fatal(handle.writes.Load())
	}
}

func TestSYNEventsDrainWhileProducerFinishes(t *testing.T) {
	// Exercise the final empty-read/finished-notification interleaving repeatedly.
	// All producers exit before finished is closed, as in scanWithEvents.
	for round := 0; round < 500; round++ {
		scanner := testBoundedSYNScanner(nil)
		scanner.eventReady = make(chan struct{}, 1)
		finished, exited := make(chan struct{}), make(chan struct{})
		var received int
		go func() { scanner.dispatchOpenEvents(func(OpenPort) { received++ }, finished); close(exited) }()
		for i := 1; i <= 4; i++ {
			scanner.addOpenPorts(synPendingProbe{port: i, hosts: []string{"192.0.2.1"}})
			runtime.Gosched()
		}
		close(finished)
		awaitSYN(t, exited)
		if received != 4 {
			t.Fatalf("round=%d callbacks=%d want 4", round, received)
		}
	}
}

type testSYNClosingSender struct {
	*boundedSYNSender
	closeFn func()
}

func (s *testSYNClosingSender) close() { s.closeFn() }

func TestSYNCancellationDuringNativeCloseWaitsAndPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	sender := &testSYNClosingSender{boundedSYNSender: &boundedSYNSender{calls: make(map[string][]uint16)}, closeFn: func() { close(entered); <-release }}
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	done := make(chan error, 1)
	go func() { done <- scanner.scanWithEvents(ctx, testSYNTasks("192.0.2.1", 1), nil) }()
	awaitSYN(t, entered)
	cancel()
	select {
	case err := <-done:
		t.Fatalf("acknowledged before native close: %v", err)
	default:
	}
	unblock()
	if err := awaitSYN(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation swallowed: %v", err)
	}
}

func TestSYNSharedHandleRecoversWithoutDroppingFailedPort(t *testing.T) {
	broken := &testSYNHandle{write: func([]byte) error { return errors.New("adapter write failure") }}
	good := &testSYNHandle{}
	deps := testSYNDependencies(good)
	var opens atomic.Int32
	deps.open = func(string) (synWriteHandle, error) {
		if opens.Add(1) == 1 {
			return broken, nil
		}
		return good, nil
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	// Prepare both routes first: recovery must update the same shared object.
	for _, ip := range []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)} {
		if _, err := sender.prepare(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
	}
	scanner := testBoundedSYNScanner(nil)
	scanner.packetSender = sender
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	if err := scanner.scan(context.Background(), append(testSYNTasks("192.0.2.1", 2), testSYNTasks("192.0.2.2", 2)...)); err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 2 || broken.writes.Load() != 1 || good.writes.Load() != 4 || final.Failed != 1 || final.Sent != 4 || final.Skipped != 0 || final.SendHandles != 2 {
		t.Fatalf("opens=%d broken=%d good=%d diagnostic=%+v", opens.Load(), broken.writes.Load(), good.writes.Load(), final)
	}
	sender.close()
	sender.close()
	if broken.closes.Load() != 1 || good.closes.Load() != 1 {
		t.Fatalf("closes=%d/%d", broken.closes.Load(), good.closes.Load())
	}
}

func TestSYNSharedHandleRecoveryBudgetIsPerInterface(t *testing.T) {
	var opened []*testSYNHandle
	deps := testSYNDependencies(nil)
	deps.open = func(string) (synWriteHandle, error) {
		h := &testSYNHandle{write: func([]byte) error { return errors.New("persistent write failure") }}
		opened = append(opened, h)
		return h, nil
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	// Serial preparation here makes opened test bookkeeping single-threaded.
	for i := 1; i <= 32; i++ {
		if _, err := sender.prepare(context.Background(), net.IPv4(198, 51, 100, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 32; i++ {
		for retry := 0; retry < 3; retry++ {
			if _, err := sender.sendTCP(context.Background(), net.IPv4(198, 51, 100, byte(i)), 40000, 80, 1, 0, tcpFlagSYN, 1024); err == nil {
				t.Fatal("expected persistent failure")
			}
		}
	}
	if len(opened) != 4 {
		t.Fatalf("opened=%d want initial+3 recovery attempts", len(opened))
	}
	sender.close()
	for _, h := range opened {
		if h.writes.Load() != 1 || h.closes.Load() != 1 {
			t.Fatalf("writes=%d closes=%d", h.writes.Load(), h.closes.Load())
		}
	}
}

func TestSYNReopenCancellationStillClosesNewHandle(t *testing.T) {
	broken := &testSYNHandle{write: func([]byte) error { return errors.New("write failure") }}
	good := &testSYNHandle{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := testSYNDependencies(broken)
	opens := 0
	deps.open = func(string) (synWriteHandle, error) {
		opens++
		if opens == 1 {
			return broken, nil
		}
		cancel()
		return good, nil
	}
	sender := newSYNLayer2Sender(time.Second, deps)
	defer sender.close()
	ip := net.IPv4(192, 0, 2, 1)
	if _, err := sender.prepare(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.sendTCP(ctx, ip, 40000, 80, 1, 0, tcpFlagSYN, 1024); err == nil {
		t.Fatal("expected failed write")
	}
	if _, err := sender.sendTCP(ctx, ip, 40000, 80, 1, 0, tcpFlagSYN, 1024); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	sender.close()
	if opens != 2 || broken.closes.Load() != 1 || good.closes.Load() != 1 || good.writes.Load() != 0 {
		t.Fatalf("opens=%d closes=%d/%d writes=%d", opens, broken.closes.Load(), good.closes.Load(), good.writes.Load())
	}
}
