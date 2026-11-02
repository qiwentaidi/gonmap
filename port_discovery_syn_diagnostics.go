package gonmap

import "time"

// SYNDiscoveryDiagnostics describes one native discovery call, not a complete
// scan/fingerprint pipeline. Failed counts failed send-path calls (including
// exhausted interface recovery budgets); Skipped
// counts probes not sent. Attempted = Sent + Skipped. On cancellation Attempted
// may be smaller than Total. Done means preparation/send/receive have exited;
// result callbacks and native Close may still be draining. It is not success.
// On Windows preparation happens concurrently, before sending. PrepareDuration
// sums consumed host results; RouteDuration includes all preparation workers,
// including canceled work and shared-cache waits. SourceDuration is contained
// in preparation time. These worker-time sums can exceed wall-clock Elapsed.
// SendDuration excludes Windows preparation; WriteDuration includes SYN and RST.
// Raw-IP SendDuration still contains SourceDuration. Timings overlap and must
// not be added together. Callbacks and setup are outside SendDuration.
type SYNDiscoveryDiagnostics struct {
	Total, Attempted, Sent, Failed, Skipped, UnreachableHosts int
	PreparedHosts, PrepareFailures                            int
	NeighborAttempts, NeighborCacheHits, SendHandles          int

	Elapsed, PrepareDuration, SourceDuration   time.Duration
	SendDuration, RouteDuration, WriteDuration time.Duration

	LastError, Error string
	Done             bool
}
