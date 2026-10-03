//go:build windows

// This file recovers the owning process of a connection when the proxy core
// does not report it.
//
// mihomo only fills in metadata.processPath when it is built with process
// matching support AND the platform lookup succeeds; sing-box reports it only
// for certain inbound types. When the field is empty the UI would show nothing,
// so the source port is mapped back to a PID through the Windows TCP table and
// then to an executable name — the same information, obtained locally.
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"vvpn/internal/netutil"
)

var (
	iphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	kernel32dll              = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess          = kernel32dll.NewProc("OpenProcess")
	procQueryFullProcessName = kernel32dll.NewProc("QueryFullProcessImageNameW")
	procCloseHandle          = kernel32dll.NewProc("CloseHandle")
)

const (
	afInet              = 2
	tcpTableOwnerPidAll = 5
	processQueryLimited = 0x1000
)

// tcpRow mirrors MIB_TCPROW_OWNER_PID.
type tcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

var (
	procCacheMu sync.Mutex
	procCache   = map[uint32]procCacheEntry{}
)

type procCacheEntry struct {
	name string
	at   time.Time
}

// processByLocalPort finds the process that owns a local TCP port. source is
// the connection's local address as the core reports it ("ip:port").
func processByLocalPort(source string) string {
	_, portStr, err := splitHostPortLoose(source)
	if err != nil {
		return ""
	}
	pid, err := pidForLocalPort(portStr)
	if err != nil || pid == 0 {
		return ""
	}
	return processName(pid)
}

func splitHostPortLoose(addr string) (string, uint16, error) {
	host, portStr, err := netutil.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := netutil.ParsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// pidForLocalPort walks the TCP owner table looking for a listening/connected
// socket whose local port matches.
func pidForLocalPort(port uint16) (uint32, error) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return 0, fmt.Errorf("proclookup: empty TCP table (ret=%d)", ret)
	}
	buf := make([]byte, size)
	ret, _, callErr := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, afInet, tcpTableOwnerPidAll, 0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("proclookup: GetExtendedTcpTable failed: %v", callErr)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(tcpRow{}))
	base := unsafe.Pointer(&buf[4])
	for i := 0; i < int(count); i++ {
		row := (*tcpRow)(unsafe.Add(base, i*rowSize))
		// Ports are stored in network byte order in the low 16 bits.
		localPort := uint16(row.LocalPort>>8) | uint16(row.LocalPort<<8)
		if localPort == port {
			return row.OwningPid, nil
		}
	}
	return 0, fmt.Errorf("proclookup: no process owns local port %d", port)
}

// processName resolves a PID to an executable name, with a short cache because
// the table is refreshed often.
func processName(pid uint32) string {
	procCacheMu.Lock()
	if entry, ok := procCache[pid]; ok && time.Since(entry.at) < 30*time.Second {
		procCacheMu.Unlock()
		return entry.name
	}
	procCacheMu.Unlock()

	handle, _, _ := procOpenProcess.Call(processQueryLimited, 0, uintptr(pid))
	if handle == 0 {
		return ""
	}
	defer func() { _, _, _ = procCloseHandle.Call(handle) }()

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessName.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return ""
	}
	full := syscall.UTF16ToString(buf[:size])
	name := filepath.Base(strings.TrimSpace(full))

	procCacheMu.Lock()
	procCache[pid] = procCacheEntry{name: name, at: time.Now()}
	procCacheMu.Unlock()
	return name
}

// processPathByPID is kept for symmetry with the non-Windows implementation.
func processPathByPID(pid uint32) string {
	handle, _, _ := procOpenProcess.Call(processQueryLimited, 0, uintptr(pid))
	if handle == 0 {
		return ""
	}
	defer func() { _, _, _ = procCloseHandle.Call(handle) }()
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessName.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// selfName helps tests assert the lookup works for a process we control.
func selfName() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Base(exe)
	}
	return ""
}
