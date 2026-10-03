//go:build windows

package winreg

import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

// Machine-wide reads. syan-clash never writes here; it only asks Windows where the
// machine currently sends its DNS queries, which is what the leak panel
// compares against the resolvers the user configured.
const hkeyLocalMachine = 0x80000002

// keyRead is KEY_READ. RegEnumKeyEx needs KEY_ENUMERATE_SUB_KEYS, which
// KEY_QUERY_VALUE alone does not grant: opening an interface list in order to
// walk it has to ask for read access, or the enumeration is denied and the
// caller silently sees an empty list.
const keyRead = 0x20019

// errorNoMoreItems is ERROR_NO_MORE_ITEMS, the natural end of an enumeration.
const errorNoMoreItems = 259

var procRegEnumKeyExW = advapi32.NewProc("RegEnumKeyExW")

// GetMachineString reads a value from HKLM. A REG_DWORD is rendered as its
// decimal form, because Windows stores a couple of the network switches that
// way and the caller only ever wants the number.
func GetMachineString(keyPath, name string) (string, error) {
	typ, data, err := readValueRoot(hkeyLocalMachine, keyPath, name)
	if err != nil {
		return "", err
	}
	switch typ {
	case regSZ, regExpandSZ:
		return decodeUTF16(data), nil
	case regDWORD:
		if len(data) >= 4 {
			return strconv.FormatUint(uint64(data[0])|uint64(data[1])<<8|uint64(data[2])<<16|uint64(data[3])<<24, 10), nil
		}
	}
	return "", fmt.Errorf("winreg: HKLM\\%s\\%s 的类型 %d 不是字符串", keyPath, name, typ)
}

// SubKeysMachine lists the immediate subkeys of an HKLM key. The network
// adapters live in one such list, and each adapter carries its own resolvers.
func SubKeysMachine(keyPath string) ([]string, error) {
	h, err := openKeyRoot(hkeyLocalMachine, keyPath, keyRead, false)
	if err != nil {
		return nil, err
	}
	defer closeKey(h)

	var out []string
	for i := uint32(0); ; i++ {
		buf := make([]uint16, 256)
		size := uint32(len(buf))
		ret, _, _ := procRegEnumKeyExW.Call(
			h,
			uintptr(i),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // reserved
			0, // class
			0, // class length
			0, // last write time
		)
		if ret == errorNoMoreItems {
			break
		}
		if ret != errorSuccess {
			return out, fmt.Errorf("winreg: 枚举 HKLM\\%s 失败：%v", keyPath, syscall.Errno(ret))
		}
		out = append(out, syscall.UTF16ToString(buf[:size]))
	}
	return out, nil
}
