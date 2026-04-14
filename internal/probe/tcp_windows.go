//go:build windows

package probe

import (
	"syscall"
)

// setTCPTTL on Windows returns nil — Windows does not support per-socket IP_TTL
// via the standard net.Dialer.Control interface at compile time without CGO.
// Full TTL traceroute on Windows requires IPHLPAPI or raw sockets (admin only).
func setTCPTTL(_ int) func(network, address string, c syscall.RawConn) error {
	return nil
}
