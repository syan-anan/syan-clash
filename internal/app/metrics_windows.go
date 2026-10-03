//go:build windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// The Windows half of the status metrics. Everything here goes through
// syscall.NewLazyDLL: the module has no dependency on golang.org/x/sys and the
// standard library exposes no wrapper for these calls.
//
// kernel32dll, procOpenProcess and procCloseHandle are declared in
// proclookup_windows.go; they are reused here instead of being re-declared,
// because two LazyDLL values for the same module would be pure waste.

var (
	psapiDLL                   = syscall.NewLazyDLL("psapi.dll")
	procGetProcessMemoryInfo   = psapiDLL.NewProc("GetProcessMemoryInfo")
	procGetProcessHandleCount  = kernel32dll.NewProc("GetProcessHandleCount")
	procCreateToolhelpSnapshot = kernel32dll.NewProc("CreateToolhelp32Snapshot")
	procThread32First          = kernel32dll.NewProc("Thread32First")
	procThread32Next           = kernel32dll.NewProc("Thread32Next")
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	th32csSnapThread        = 0x00000004
)

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// threadEntry32 mirrors THREADENTRY32.
type threadEntry32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// selfMetrics reads the counters of the process this code runs in.
func selfMetrics() procMetrics {
	// GetCurrentProcess returns the kernel pseudo-handle, which is all the
	// two query calls below need: it always refers to this process and never
	// has to be closed.
	handle, _ := syscall.GetCurrentProcess()
	return procMetrics{
		RSSBytes: workingSetBytes(uintptr(handle)),
		Threads:  threadCount(os.Getpid()),
		Handles:  handleCount(uintptr(handle)),
	}
}

// processMetrics reads the counters of another process. Every failure path
// returns zeroes instead of an error: the response must stay shaped the same
// when a core dies between the supervisor lookup and this call.
func processMetrics(pid int) procMetrics {
	if pid <= 0 {
		return procMetrics{}
	}
	handle, _, _ := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if handle == 0 {
		// A core that is alive but already half-torn-down may refuse the full
		// rights; the limited query right is enough for all three calls.
		handle, _, _ = procOpenProcess.Call(processQueryLimited, 0, uintptr(pid))
	}
	if handle == 0 {
		return procMetrics{}
	}
	defer func() { _, _, _ = procCloseHandle.Call(handle) }()
	return procMetrics{
		RSSBytes: workingSetBytes(handle),
		Threads:  threadCount(pid),
		Handles:  handleCount(handle),
	}
}

// workingSetBytes returns the current working set, which is the Windows name
// for the resident set the UI labels "RSS".
func workingSetBytes(handle uintptr) uint64 {
	var counters processMemoryCounters
	counters.Cb = uint32(unsafe.Sizeof(counters))
	ret, _, _ := procGetProcessMemoryInfo.Call(
		handle,
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.Cb),
	)
	if ret == 0 {
		return 0
	}
	return uint64(counters.WorkingSetSize)
}

// handleCount returns the number of open handles the process holds.
func handleCount(handle uintptr) int {
	var count uint32
	ret, _, _ := procGetProcessHandleCount.Call(handle, uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0
	}
	return int(count)
}

// threadCount walks the system thread snapshot and counts the threads owned by
// pid. A snapshot needs no handle on the target, so it also works for the
// current process, whose pseudo-handle has no PID a snapshot could match.
func threadCount(pid int) int {
	if pid <= 0 {
		return 0
	}
	snap, _, _ := procCreateToolhelpSnapshot.Call(th32csSnapThread, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return 0
	}
	defer func() { _, _, _ = procCloseHandle.Call(snap) }()

	var entry threadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procThread32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}
	count := 0
	for {
		if int(entry.OwnerProcessID) == pid {
			count++
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procThread32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			return count
		}
	}
}
