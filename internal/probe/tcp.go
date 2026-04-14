package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCPProber implements Prober using TCP SYN connections.
// It works without root privileges but cannot directly observe intermediate hops.
// TTL-based hop detection requires raw socket access; when unavailable the prober
// only measures end-to-end latency (TTL is stored in Result but hop detection is
// limited to the final target).
type TCPProber struct {
	port int
}

// NewTCPProber creates a TCP prober targeting the given port.
func NewTCPProber(port int) *TCPProber {
	return &TCPProber{port: port}
}

func (p *TCPProber) Name() string { return fmt.Sprintf("TCP/%d", p.port) }

// Probe performs a TCP connect to target:port and returns latency.
// TTL-limited traceroute is NOT supported in this fallback implementation;
// every probe reports Reached=true and RespondingIP=target.
func (p *TCPProber) Probe(ctx context.Context, target net.IP, ttl int, _ uint16, timeout time.Duration) (*Result, error) {
	addr := fmt.Sprintf("%s:%d", target.String(), p.port)
	sentAt := time.Now()

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: setTCPTTL(ttl), // platform-specific TTL hook (may be no-op)
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	rtt := time.Since(sentAt)

	if err != nil {
		// Distinguish timeout from refusal
		if isTimeout(err) {
			return &Result{TTL: ttl, At: sentAt, Success: false}, nil
		}
		// Connection refused still means we reached the host
		return &Result{
			TTL:          ttl,
			RespondingIP: target,
			RTT:          rtt,
			Success:      true,
			Reached:      true,
			At:           sentAt,
		}, nil
	}
	conn.Close()

	return &Result{
		TTL:          ttl,
		RespondingIP: target,
		RTT:          rtt,
		Success:      true,
		Reached:      true,
		At:           sentAt,
	}, nil
}

func (p *TCPProber) Close() error { return nil }

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
