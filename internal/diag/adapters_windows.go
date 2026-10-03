//go:build windows

package diag

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// Windows keeps a resolver configuration for every adapter it has ever seen,
// including ones that were unplugged long ago. GetAdaptersAddresses answers
// which of them are connected right now, so the leak panel does not accuse a
// decommissioned adapter's resolver of leaking anything.
const (
	adapterFlagSkipUnicast   = 0x0001
	adapterFlagSkipAnycast   = 0x0002
	adapterFlagSkipMulticast = 0x0004
	adapterFlagSkipDNSServer = 0x0008

	adapterBufferOverflow = 111
	ifOperStatusUp        = 1

	// Offsets inside IP_ADAPTER_ADDRESSES on 64-bit Windows: the leading
	// union is 8 bytes, then the Next pointer, then AdapterName. OperStatus
	// sits after PhysicalAddress, Flags, Mtu and IfType.
	adapterOffsetNext       = 8
	adapterOffsetName       = 16
	adapterOffsetOperStatus = 104
	adapterStructSize       = 112

	adapterWalkLimit = 64
	adapterNameLimit = 256
)

var (
	iphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

// activeAdapters reports the connected adapters by GUID, or nil when the state
// could not be read (in which case the caller shows everything).
func activeAdapters() map[string]bool {
	// The struct offsets below are the 64-bit layout; on any other word size
	// this returns "unknown" rather than guessing.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil
	}
	buf := make([]byte, 16<<10)
	var size uint32
	for attempt := 0; ; attempt++ {
		if attempt > 3 {
			return nil
		}
		size = uint32(len(buf))
		ret, _, _ := procGetAdaptersAddresses.Call(
			uintptr(0), // AF_UNSPEC
			uintptr(adapterFlagSkipUnicast|adapterFlagSkipAnycast|adapterFlagSkipMulticast|adapterFlagSkipDNSServer),
			0, // reserved
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret == 0 {
			break
		}
		if ret != adapterBufferOverflow {
			return nil
		}
		buf = make([]byte, size)
	}

	out := map[string]bool{}
	first := uintptr(unsafe.Pointer(&buf[0]))
	for cur, n := first, 0; cur != 0 && n < adapterWalkLimit; n++ {
		off := cur - first
		if off+adapterStructSize > uintptr(len(buf)) {
			break
		}
		name := readAnsiString(uintptr(binary.LittleEndian.Uint64(buf[off+adapterOffsetName:])))
		status := binary.LittleEndian.Uint32(buf[off+adapterOffsetOperStatus:])
		if name != "" && status == ifOperStatusUp {
			out[normalizeGUID(name)] = true
		}
		cur = uintptr(binary.LittleEndian.Uint64(buf[off+adapterOffsetNext:]))
	}
	return out
}

// readAnsiString reads a NUL-terminated byte string out of the adapter buffer.
func readAnsiString(p uintptr) string {
	if p == 0 {
		return ""
	}
	var b []byte
	for i := 0; i < adapterNameLimit; i++ {
		c := *(*byte)(unsafe.Pointer(p + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}
