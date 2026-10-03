//go:build !windows

package app

// Non-Windows builds have no equivalent of the Windows process counters, so
// the fields are reported as zero. The client ships for Windows only; this
// file exists so the package still builds and vets elsewhere.

// selfMetrics reports zeroes for the current process.
func selfMetrics() procMetrics { return procMetrics{} }

// processMetrics reports zeroes for any PID.
func processMetrics(pid int) procMetrics { return procMetrics{} }
