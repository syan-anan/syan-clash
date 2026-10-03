//go:build windows

package core

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// A job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ties the lifetime of the
// spawned cores to this process: if the console is force-killed, Windows kills
// the cores too instead of leaving orphans holding the proxy ports.
var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")

	jobOnce   sync.Once
	jobHandle uintptr
)

const (
	jobInfoClassExtendedLimit    = 9
	jobObjectLimitKillOnJobClose = 0x2000

	processTerminate = 0x0001
	processSetQuota  = 0x0100
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
	// Windows validates the exact structure size for
	// JobObjectExtendedLimitInformation. The fields above total 136 bytes, but
	// the API only accepts 144 (measured: 136 -> ERROR_BAD_LENGTH, 144 -> ok),
	// so the trailing padding is part of the ABI.
	_ [8]byte
}

var jobErr error

func ensureJob() (uintptr, error) {
	jobOnce.Do(func() {
		handle, _, callErr := procCreateJobObjectW.Call(0, 0)
		if handle == 0 {
			jobErr = fmt.Errorf("CreateJobObject: %v", callErr)
			return
		}
		info := jobExtendedLimitInfo{}
		info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
		ret, _, callErr := procSetInformationJobObject.Call(
			handle,
			uintptr(jobInfoClassExtendedLimit),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
		)
		if ret == 0 {
			jobErr = fmt.Errorf("SetInformationJobObject: %v", callErr)
			return
		}
		jobHandle = handle
	})
	if jobHandle == 0 {
		if jobErr == nil {
			jobErr = fmt.Errorf("job object unavailable")
		}
		return 0, jobErr
	}
	return jobHandle, nil
}

// attachToJob puts a freshly started child into the kill-on-close job.
func attachToJob(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("no process handle")
	}
	job, err := ensureJob()
	if err != nil {
		return err
	}
	handle, err := syscall.OpenProcess(processTerminate|processSetQuota, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", cmd.Process.Pid, err)
	}
	defer syscall.CloseHandle(handle)
	ret, _, callErr := procAssignProcessToJobObject.Call(job, uintptr(handle))
	if ret == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %v", callErr)
	}
	return nil
}
