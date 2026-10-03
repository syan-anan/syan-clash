//go:build windows

package diag

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

// ICMP goes straight to iphlpapi. No command line, no child process - the
// promise this whole client is built around.

var (
	iphlpapiDLL         = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapiDLL.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapiDLL.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapiDLL.NewProc("IcmpSendEcho")
)

const (
	ipFlagDF            = 0x02
	ipSuccess           = 0
	ipTTLExpiredTransit = 11013 // a router on the way answered instead
	ipReqTimedOut       = 11010 // ERROR_IP_REQ_TIMED_OUT
	wsaAccessDenied     = 10013
	errorAccessDenied   = 5
	// icmpEchoReplySize is sizeof(ICMP_ECHO_REPLY) on x64: address, status,
	// round trip time, two sizes and the data pointer. Reply buffers are
	// sized with extra room because the kernel appends the payload there.
	icmpEchoReplySize = 32
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData unsafe.Pointer
}

// icmpReplyHeader mirrors ICMP_ECHO_REPLY up to the trailing pointer.
type icmpReplyHeader struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          unsafe.Pointer
}

// icmpProbe sends one echo request and reports who answered. status 0 is the
// destination; TTL-expired marks a router on the way.
func icmpProbe(dst netip.Addr, ttl, payload int, df bool, timeout time.Duration) (icmpReply, error) {
	if !dst.Is4() {
		return icmpReply{}, errors.New("icmp: not an IPv4 address")
	}
	if payload < 0 {
		payload = 0
	}
	if payload > 65500 {
		payload = 65500
	}
	if ttl < 1 {
		ttl = 1
	}
	if ttl > 255 {
		ttl = 255
	}
	handle, _, _ := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return icmpReply{}, errICMPUnavailable
	}
	defer procIcmpCloseHandle.Call(handle)

	req := make([]byte, payload)
	for i := range req {
		req[i] = byte(i % 251)
	}
	opts := ipOptionInformation{TTL: uint8(ttl)}
	if df {
		opts.Flags = ipFlagDF
	}
	reply := make([]byte, icmpEchoReplySize+payload+16)
	var reqPtr uintptr
	if len(req) > 0 {
		reqPtr = uintptr(unsafe.Pointer(&req[0]))
	}
	dstIP := dst.As4()

	ret, _, callErr := procIcmpSendEcho.Call(
		handle,
		uintptr(binary.BigEndian.Uint32(dstIP[:])),
		reqPtr,
		uintptr(payload),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeout.Milliseconds()),
	)
	if ret == 0 {
		if errno, ok := callErr.(syscall.Errno); ok {
			switch uintptr(errno) {
			case wsaAccessDenied, errorAccessDenied:
				return icmpReply{}, errICMPUnavailable
			}
		}
		return icmpReply{}, errICMPTimeout
	}
	hdr := (*icmpReplyHeader)(unsafe.Pointer(&reply[0]))
	switch hdr.Status {
	case ipSuccess:
		return icmpReply{
			From:  ipFromUint32(hdr.Address),
			RTT:   time.Duration(hdr.RoundTripTime) * time.Millisecond,
			Final: true,
		}, nil
	case ipTTLExpiredTransit:
		return icmpReply{
			From: ipFromUint32(hdr.Address),
			RTT:  time.Duration(hdr.RoundTripTime) * time.Millisecond,
		}, nil
	}
	// Any other status is treated as an unanswered probe: the hop shows as a
	// timeout rather than stopping the walk.
	return icmpReply{}, errICMPTimeout
}
