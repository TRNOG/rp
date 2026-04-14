package renderer

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alptekinsunnetci/netplotter/internal/config"
	"github.com/alptekinsunnetci/netplotter/internal/metrics"
)

// ANSI escape codes
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiWhite  = "\033[97m"
	ansiDim    = "\033[2m"

	clearLine  = "\033[2K"
	cursorHome = "\033[H"
	hideCursor = "\033[?25l"
	showCursor = "\033[?25h"

	// Alternate screen buffer — keeps the main terminal scrollback clean and
	// gives us a guaranteed fresh viewport to overwrite on every frame.
	altScreenEnter = "\033[?1049h"
	altScreenExit  = "\033[?1049l"
)

// Sparkline characters — 8 levels, lowest to highest bar
var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Fixed column widths
const (
	colHop    = 4
	colIP     = 18
	colHost   = 28
	colLoss   = 7
	colLast   = 8
	colAvg    = 8
	colMin    = 8
	colMax    = 8
	colJitter = 8
	colGraph  = 20
)

// TerminalRenderer renders the hop table to a terminal using ANSI codes.
type TerminalRenderer struct {
	out io.Writer
	cfg *config.Config
}

// NewTerminalRenderer creates a TerminalRenderer writing to stdout.
// It enters the alternate screen buffer so the main scrollback is not
// polluted; Close() restores everything on exit.
func NewTerminalRenderer(cfg *config.Config) *TerminalRenderer {
	enableANSI() // enable VT processing on Windows; no-op on Unix
	r := &TerminalRenderer{out: os.Stdout, cfg: cfg}
	// Enter alternate screen + hide cursor.
	fmt.Fprint(r.out, altScreenEnter+hideCursor)
	return r
}

// Close exits the alternate screen and restores the cursor.
func (r *TerminalRenderer) Close() {
	fmt.Fprint(r.out, altScreenExit+showCursor)
}

// Render draws the full table, overwriting the previous frame in place.
// Because we're in the alternate screen buffer, cursor-home + overwrite is
// guaranteed to be clean — no scrollback pollution, no off-by-one on Windows.
func (r *TerminalRenderer) Render(snaps []metrics.HopSnapshot, summary metrics.SessionSummary, routeChanged bool) {
	var b strings.Builder

	// Jump to top-left of the alternate screen on every frame.
	b.WriteString(cursorHome)

	// ── Header ──────────────────────────────────────────────────────────────
	for _, line := range r.buildHeader(summary, routeChanged) {
		b.WriteString(clearLine)
		b.WriteString(line)
		b.WriteString("\r\n")
	}

	// ── Column titles ────────────────────────────────────────────────────────
	b.WriteString(clearLine)
	b.WriteString(r.buildColumnHeader())
	b.WriteString("\r\n")

	b.WriteString(clearLine)
	b.WriteString(r.buildSeparator())
	b.WriteString("\r\n")

	// ── Hop rows ─────────────────────────────────────────────────────────────
	// Always show every hop — including routers that don't send TTL-exceeded
	// (shown as "* * *" like classic traceroute).
	for _, snap := range snaps {
		if snap.TTL == 0 {
			continue
		}
		neverReplied := snap.IP == nil && snap.Recv == 0

		b.WriteString(clearLine)
		if neverReplied {
			b.WriteString(r.buildNoReplyRow(snap))
		} else {
			b.WriteString(r.buildHopRow(snap))
		}
		b.WriteString("\r\n")
	}

	// ── Footer ───────────────────────────────────────────────────────────────
	b.WriteString(clearLine)
	b.WriteString(r.buildFooter(snaps, summary))
	b.WriteString("\r\n")

	// Erase any leftover lines from a previously longer frame.
	b.WriteString("\033[J")

	fmt.Fprint(r.out, b.String())
}

// ── Private helpers ──────────────────────────────────────────────────────────

func (r *TerminalRenderer) buildHeader(sum metrics.SessionSummary, routeChanged bool) []string {
	title := r.color(ansiBold+ansiCyan, "netplotter") + " — " +
		r.color(ansiWhite, sum.Target.String()) +
		"  │  uptime: " + r.color(ansiGreen, formatDuration(sum.Duration))

	if routeChanged {
		title += "  " + r.color(ansiYellow, "⚠ ROUTE CHANGED")
	}
	return []string{title, ""}
}

func (r *TerminalRenderer) buildColumnHeader() string {
	type col struct {
		w int
		s string
	}
	cols := []col{
		{colHop, "Hop"}, {colIP, " IP Address"}, {colHost, "Hostname"},
		{colLoss, "Loss%"}, {colLast, "Last"}, {colAvg, "Avg"},
		{colMin, "Min"}, {colMax, "Max"}, {colJitter, "Jitter"},
		{colGraph, "Graph (last 20)"},
	}
	var b strings.Builder
	for _, c := range cols {
		b.WriteString(r.color(ansiBold+ansiWhite, padRight(c.s, c.w)))
	}
	return b.String()
}

func (r *TerminalRenderer) buildSeparator() string {
	total := colHop + colIP + colHost + colLoss + colLast + colAvg + colMin + colMax + colJitter + colGraph
	return r.color(ansiDim, strings.Repeat("─", total))
}

// buildNoReplyRow renders a "* * *" row for a hop that never sent TTL-exceeded.
// These routers simply don't respond; this is policy, not packet loss.
// A leading space in the IP cell visually separates the hop number from the *.
func (r *TerminalRenderer) buildNoReplyRow(snap metrics.HopSnapshot) string {
	var b strings.Builder
	b.WriteString(r.color(ansiDim, padLeft(fmt.Sprintf("%d", snap.TTL), colHop)))
	b.WriteString(r.color(ansiDim, padRight(" *", colIP)))   // leading space → no "1*" clash
	b.WriteString(r.color(ansiDim, padRight("(no reply)", colHost)))
	b.WriteString(r.color(ansiDim, padRight("-", colLoss)))
	b.WriteString(r.color(ansiDim, padRight("-", colLast)))
	b.WriteString(r.color(ansiDim, padRight("-", colAvg)))
	b.WriteString(r.color(ansiDim, padRight("-", colMin)))
	b.WriteString(r.color(ansiDim, padRight("-", colMax)))
	b.WriteString(r.color(ansiDim, padRight("-", colJitter)))
	b.WriteString(strings.Repeat(" ", colGraph))
	return b.String()
}

func (r *TerminalRenderer) buildHopRow(snap metrics.HopSnapshot) string {
	var b strings.Builder

	// Hop number
	b.WriteString(r.color(ansiDim, padLeft(fmt.Sprintf("%d", snap.TTL), colHop)))

	// IP — leading space separates the right-aligned hop number from the address.
	ipStr := snap.DisplayIP()
	b.WriteString(padRight(" "+ipStr, colIP))

	// Hostname (omit when it equals the IP string)
	host := snap.DisplayName()
	if host == ipStr {
		host = ""
	}
	b.WriteString(r.color(ansiDim, padRight(truncate(host, colHost-1), colHost)))

	// No probes sent yet (hop was registered from traceroute but round hasn't run)
	if snap.Sent == 0 {
		b.WriteString(r.color(ansiDim, strings.Repeat("·", colLoss+colLast+colAvg+colMin+colMax+colJitter+colGraph)))
		return b.String()
	}

	// Loss %
	lossStr := fmt.Sprintf("%.1f%%", snap.Loss*100)
	b.WriteString(r.color(r.lossColor(snap.Loss), padRight(lossStr, colLoss)))

	// RTT columns
	if snap.Recv == 0 {
		for _, w := range []int{colLast, colAvg, colMin, colMax, colJitter} {
			b.WriteString(r.color(ansiRed, padRight("???", w)))
		}
	} else {
		latColor := r.latencyColor(snap.AvgRTT)
		b.WriteString(r.color(latColor, padRight(fmtDur(snap.LastRTT), colLast)))
		b.WriteString(r.color(latColor, padRight(fmtDur(snap.AvgRTT), colAvg)))
		b.WriteString(r.color(ansiDim, padRight(fmtDur(snap.MinRTT), colMin)))
		b.WriteString(r.color(ansiDim, padRight(fmtDur(snap.MaxRTT), colMax)))
		b.WriteString(r.color(ansiDim, padRight(fmtDur(snap.Jitter), colJitter)))
	}

	// Sparkline
	b.WriteString(r.color(r.latencyColor(snap.AvgRTT), r.sparkline(snap.RecentRTTs, colGraph)))

	return b.String()
}

// buildFooter shows end-to-end loss using only the LAST responding hop.
// Using the session total (all hops) would give a falsely high loss % because
// intermediate routers that don't send TTL-exceeded look like 100% loss.
func (r *TerminalRenderer) buildFooter(snaps []metrics.HopSnapshot, sum metrics.SessionSummary) string {
	// Walk backwards to find the last hop that has actually replied.
	var last *metrics.HopSnapshot
	for i := len(snaps) - 1; i >= 0; i-- {
		if snaps[i].Recv > 0 || (snaps[i].Sent > 0 && snaps[i].IP != nil) {
			cp := snaps[i]
			last = &cp
			break
		}
	}

	// Count silent hops (* * *) — routers that don't send TTL-exceeded.
	silent := 0
	for _, s := range snaps {
		if s.IP == nil && s.Recv == 0 {
			silent++
		}
	}

	info := ""
	if last != nil && last.Sent > 0 {
		info = fmt.Sprintf("  e2e loss: %.1f%%  (%d sent, %d recv)  route changes: %d",
			last.Loss*100, last.Sent, last.Recv, sum.RouteChanges)
	}
	silentNote := ""
	if silent > 0 {
		silentNote = fmt.Sprintf("  [%d hop(s) show * — routers blocking ICMP TTL-exceeded, normal for CDN/cloud paths]", silent)
	}
	return r.color(ansiDim, "Ctrl+C to quit."+info+silentNote)
}

// sparkline builds a Unicode bar chart from the given RTT slice.
func (r *TerminalRenderer) sparkline(rtts []time.Duration, w int) string {
	if len(rtts) == 0 {
		return strings.Repeat(" ", w)
	}
	if len(rtts) > w {
		rtts = rtts[len(rtts)-w:]
	}

	var minV, maxV float64
	minV = math.MaxFloat64
	for _, d := range rtts {
		v := float64(d.Nanoseconds())
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	runes := make([]rune, w)
	for i := range runes {
		runes[i] = ' '
	}
	rangeV := maxV - minV
	for i, d := range rtts {
		idx := 0
		if rangeV > 0 {
			idx = int((float64(d.Nanoseconds())-minV)/rangeV*float64(len(sparkChars)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		runes[i] = sparkChars[idx]
	}
	return string(runes)
}

func (r *TerminalRenderer) color(code, s string) string {
	if r.cfg.NoColor {
		return s
	}
	return code + s + ansiReset
}

func (r *TerminalRenderer) latencyColor(rtt time.Duration) string {
	switch {
	case rtt == 0:
		return ansiDim
	case rtt < r.cfg.WarnLatency:
		return ansiGreen
	case rtt < r.cfg.CriticalLatency:
		return ansiYellow
	default:
		return ansiRed
	}
}

func (r *TerminalRenderer) lossColor(loss float64) string {
	if loss == 0 {
		return ansiGreen
	}
	if loss < r.cfg.CriticalLoss {
		return ansiYellow
	}
	return ansiRed
}

// ── Utilities ────────────────────────────────────────────────────────────────

func padRight(s string, n int) string {
	l := utf8.RuneCountInString(s)
	if l >= n {
		return s
	}
	return s + strings.Repeat(" ", n-l)
}

func padLeft(s string, n int) string {
	l := utf8.RuneCountInString(s)
	if l >= n {
		return s
	}
	return strings.Repeat(" ", n-l) + s
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[:n])
	}
	return string(runes[:n-3]) + "..."
}

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "0ms"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds()) // no decimals → always < 8 runes
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}
