//go:build !windows

package gonmap

import "time"

func newSYNLayer2PacketSender(timeout time.Duration) (synPacketSender, error) {
	return nil, errSYNDiscoveryUnavailable
}
