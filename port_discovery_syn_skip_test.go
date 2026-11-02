package gonmap

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"
)

type boundedSYNSender struct {
	calls map[string][]uint16
	send  func(context.Context, net.IP, uint16) error
}

func (s *boundedSYNSender) close() {}
func (s *boundedSYNSender) sendTCP(ctx context.Context, ip net.IP, src, dst uint16, seq, ack uint32, flags uint8, window uint16) (net.IP, error) {
	s.calls[ip.String()] = append(s.calls[ip.String()], dst)
	if s.send != nil {
		if err := s.send(ctx, ip, dst); err != nil {
			return nil, err
		}
	}
	return net.IPv4(192, 0, 2, 100), nil
}
func testBoundedSYNScanner(sender *boundedSYNSender) *synDiscoveryScanner {
	return &synDiscoveryScanner{packetSender: sender, timeout: time.Nanosecond, rate: 1000000, nextPort: synSourcePortMin, randSource: rand.New(rand.NewSource(1)), srcIPCache: make(map[string]net.IP), resolveSource: func(context.Context, net.IP, time.Duration) (net.IP, error) { return net.IPv4(192, 0, 2, 100), nil }, pending: make(map[synProbeKey]synPendingProbe), open: make(map[string]OpenPort), done: make(chan struct{})}
}
func testSYNTasks(host string, count int) []synScanTask {
	tasks := make([]synScanTask, count)
	for i := range tasks {
		tasks[i] = synScanTask{ip: net.ParseIP(host).To4(), port: i + 1, hosts: []string{host}}
	}
	return tasks
}
func TestSYNBoundsRealFailuresAndContinuesOtherHosts(t *testing.T) {
	sender := &boundedSYNSender{calls: make(map[string][]uint16), send: func(_ context.Context, ip net.IP, _ uint16) error {
		if ip.String() == "192.0.2.1" {
			return errors.New("ARP timeout")
		}
		return nil
	}}
	scanner := testBoundedSYNScanner(sender)
	tasks := append(testSYNTasks("192.0.2.1", 320), testSYNTasks("192.0.2.2", 320)...)
	unreachable := 0
	scanner.onHostUnreachable = func(host string, err error) {
		if host != "192.0.2.1" || err == nil {
			t.Fatalf("host=%s err=%v", host, err)
		}
		unreachable++
	}
	var progress []int
	scanner.onProgress = func(n, total int) {
		if total != 640 {
			t.Fatal(total)
		}
		progress = append(progress, n)
	}
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	if err := scanner.scan(context.Background(), tasks); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sender.calls["192.0.2.1"], []uint16{1, 1, 1}) || len(sender.calls["192.0.2.2"]) != 320 {
		t.Fatalf("calls=%v", sender.calls)
	}
	if unreachable != 1 || final.Attempted != 640 || final.Sent != 320 || final.Skipped != 320 || final.Failed != 3 || !final.Done || final.Error != "" {
		t.Fatalf("unreachable=%d final=%+v", unreachable, final)
	}
	if len(progress) < 3 || progress[len(progress)-1] != 640 {
		t.Fatal(progress)
	}
	for i := 1; i < len(progress); i++ {
		if progress[i] <= progress[i-1] {
			t.Fatal(progress)
		}
	}
}
func TestSYNTransientFailureRetriesSamePort(t *testing.T) {
	attempts := 0
	sender := &boundedSYNSender{calls: make(map[string][]uint16), send: func(context.Context, net.IP, uint16) error {
		attempts++
		if attempts <= 2 {
			return errors.New("temporary error")
		}
		return nil
	}}
	scanner := testBoundedSYNScanner(sender)
	scanner.onHostUnreachable = func(string, error) { t.Fatal("transient failure must not skip host") }
	if err := scanner.scan(context.Background(), testSYNTasks("192.0.2.1", 2)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sender.calls["192.0.2.1"], []uint16{1, 1, 1, 2}) {
		t.Fatal(sender.calls)
	}
}
func TestSYNSourceFailureReallyRetriesAndCanRecover(t *testing.T) {
	sender := &boundedSYNSender{calls: make(map[string][]uint16)}
	scanner := testBoundedSYNScanner(sender)
	lookups := 0
	scanner.resolveSource = func(context.Context, net.IP, time.Duration) (net.IP, error) {
		lookups++
		if lookups <= 2 {
			return nil, errors.New("temporary route error")
		}
		return net.IPv4(192, 0, 2, 100), nil
	}
	if err := scanner.scan(context.Background(), testSYNTasks("192.0.2.1", 2)); err != nil {
		t.Fatal(err)
	}
	if lookups != 3 || !reflect.DeepEqual(sender.calls["192.0.2.1"], []uint16{1, 2}) {
		t.Fatalf("lookups=%d calls=%v", lookups, sender.calls)
	}
}
func TestSYNSourceFailureBoundedEvenWithOnePort(t *testing.T) {
	for _, ports := range []int{1, 2, 320} {
		t.Run(string(rune('a'+ports%26)), func(t *testing.T) {
			scanner := testBoundedSYNScanner(&boundedSYNSender{calls: make(map[string][]uint16)})
			lookups, unreachable := 0, 0
			scanner.resolveSource = func(context.Context, net.IP, time.Duration) (net.IP, error) {
				lookups++
				return nil, errors.New("no route")
			}
			scanner.onHostUnreachable = func(string, error) { unreachable++ }
			var final SYNDiscoveryDiagnostics
			scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
			if err := scanner.scan(context.Background(), testSYNTasks("192.0.2.1", ports)); err == nil {
				t.Fatal("expected failure")
			}
			if lookups != 3 || unreachable != 1 || final.Error == "" || final.Skipped != ports {
				t.Fatalf("lookups=%d unreachable=%d final=%+v", lookups, unreachable, final)
			}
		})
	}
}
func TestSYNCancelFlushesPartialDiagnosticsWithoutUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	sender := &boundedSYNSender{calls: make(map[string][]uint16), send: func(context.Context, net.IP, uint16) error {
		n++
		if n == 7 {
			cancel()
			return context.Canceled
		}
		return nil
	}}
	scanner := testBoundedSYNScanner(sender)
	scanner.onHostUnreachable = func(string, error) { t.Fatal("cancellation is not host failure") }
	var final SYNDiscoveryDiagnostics
	scanner.onDiagnostics = func(d SYNDiscoveryDiagnostics) { final = d }
	var progress int
	scanner.onProgress = func(n, total int) { progress = n }
	if err := scanner.scan(ctx, testSYNTasks("192.0.2.1", 320)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if progress != 6 || final.Attempted != 6 || final.Failed != 0 || !final.Done || final.Error != context.Canceled.Error() {
		t.Fatalf("progress=%d final=%+v", progress, final)
	}
}
func TestSYNCallbackOptionsNormalizeAndMarshal(t *testing.T) {
	options := PortDiscoveryOptions{Mode: PortDiscoveryModeSYN, OnProgress: func(int, int) {}, OnHostUnreachable: func(string, error) {}, OnSYNDiagnostics: func(SYNDiscoveryDiagnostics) {}}
	normalized := normalizePortDiscoveryOptions(&options)
	if normalized.OnProgress == nil || normalized.OnHostUnreachable == nil || normalized.OnSYNDiagnostics == nil {
		t.Fatal("callbacks lost")
	}
	if _, err := json.Marshal(options); err != nil {
		t.Fatal(err)
	}
}

func TestSYNSetupFailureIsDiagnosed(t *testing.T) {
	var final SYNDiscoveryDiagnostics
	_, err := discoverOpenPortsSYNWithCallback(context.Background(), []string{"::1"}, []int{80}, PortDiscoveryOptions{OnSYNDiagnostics: func(d SYNDiscoveryDiagnostics) { final = d }}, nil)
	if err == nil || !final.Done || final.Error == "" {
		t.Fatalf("err=%v diagnostic=%+v", err, final)
	}
}
