// Package probe provides network probing implementations for ICMP, TCP, and UDP.
package probe

import (
	"context"
	"net"
	"time"
)

// Result holds the outcome of a single probe.
type Result struct {
	// TTL sent with this probe (used for traceroute-style probing)
	TTL int

	// RespondingIP is the IP that sent the reply.
	// For intermediate hops this is the router; for the final hop it equals the target.
	RespondingIP net.IP

	// RTT is the round-trip time. Zero when Success=false.
	RTT time.Duration

	// Success is true when we received any ICMP reply (TTL exceeded or echo reply).
	Success bool

	// Reached is true when the probe reached the final target (echo reply / TCP RST or SYN-ACK).
	Reached bool

	// At is the time the probe was sent.
	At time.Time

	// Err holds any non-timeout error.
	Err error
}

// Prober is the interface for all probing back-ends.
type Prober interface {
	// Probe sends a single probe to target with the given TTL and sequence number.
	// The prober must block until a reply arrives or timeout elapses.
	Probe(ctx context.Context, target net.IP, ttl int, seq uint16, timeout time.Duration) (*Result, error)

	// Close releases all resources held by the prober.
	Close() error

	// Name returns a human-readable name (e.g. "ICMP", "TCP/443").
	Name() string
}
