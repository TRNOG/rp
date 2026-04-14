//go:build windows

package renderer

import (
	"os"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

// enableANSI enables ANSI/VT escape-code processing on the Windows console
// and sets the console code page to UTF-8 (65001) so that Unicode block
// characters (▁▂▃▄▅▆▇█) render correctly in CMD and PowerShell.
// Requires Windows 10 version 1511+ (build 10586) or Windows Server 2016+.
func enableANSI() {
	// Set UTF-8 code page so Unicode sparkline chars render correctly.
	setCP := kernel32.NewProc("SetConsoleOutputCP")
	setCP.Call(65001)
	setInputCP := kernel32.NewProc("SetConsoleCP")
	setInputCP.Call(65001)

	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err != nil {
		return
	}
	// ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
	_ = windows.SetConsoleMode(stdout, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
