//go:build windows

package winreg

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Per-user registry access (HKCU) through advapi32, so reading or writing a
// setting never has to spawn anything.
const (
	hkeyCurrentUser = 0x80000001

	keyQueryValue = 0x0001
	keySetValue   = 0x0002

	regSZ       = 1
	regExpandSZ = 2
	regDWORD    = 4

	errorSuccess      = 0
	errorFileNotFound = 2
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW  = advapi32.NewProc("RegCreateKeyExW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW   = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW  = advapi32.NewProc("RegDeleteValueW")
	procRegDeleteTreeW   = advapi32.NewProc("RegDeleteTreeW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
)

// openKey opens (or, when create is set, creates) a subkey of HKCU.
func openKey(keyPath string, access uint32, create bool) (uintptr, error) {
	return openKeyRoot(hkeyCurrentUser, keyPath, access, create)
}

// openKeyRoot is openKey against an explicit predefined root, which is what the
// machine-wide reads (HKLM) need. The client only ever reads there.
func openKeyRoot(root uintptr, keyPath string, access uint32, create bool) (uintptr, error) {
	sub, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return 0, fmt.Errorf("winreg: %v", err)
	}
	var h uintptr
	if create {
		ret, _, _ := procRegCreateKeyExW.Call(
			root,
			uintptr(unsafe.Pointer(sub)),
			0, // reserved
			0, // class
			0, // options
			uintptr(access),
			0, // security attributes
			uintptr(unsafe.Pointer(&h)),
			0, // disposition
		)
		if ret != errorSuccess {
			return 0, fmt.Errorf("winreg: 创建键 %s 失败：%v", keyPath, syscall.Errno(ret))
		}
		return h, nil
	}
	ret, _, _ := procRegOpenKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(sub)),
		0, // options
		uintptr(access),
		uintptr(unsafe.Pointer(&h)),
	)
	if ret == errorFileNotFound {
		return 0, fmt.Errorf("winreg: 键 %s 不存在：%w", keyPath, ErrNotFound)
	}
	if ret != errorSuccess {
		return 0, fmt.Errorf("winreg: 打开键 %s 失败：%v", keyPath, syscall.Errno(ret))
	}
	return h, nil
}

func closeKey(h uintptr) {
	_, _, _ = procRegCloseKey.Call(h)
}

// readValue returns the type and the raw bytes of a value, or ErrNotFound.
func readValue(keyPath, name string) (uint32, []byte, error) {
	return readValueRoot(hkeyCurrentUser, keyPath, name)
}

// readValueRoot is readValue against an explicit predefined root.
func readValueRoot(root uintptr, keyPath, name string) (uint32, []byte, error) {
	h, err := openKeyRoot(root, keyPath, keyQueryValue, false)
	if err != nil {
		return 0, nil, err
	}
	defer closeKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, fmt.Errorf("winreg: %v", err)
	}
	var typ, size uint32
	ret, _, _ := procRegQueryValueExW.Call(
		h,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == errorFileNotFound {
		return 0, nil, ErrNotFound
	}
	if ret != errorSuccess {
		return 0, nil, fmt.Errorf("winreg: 读取 %s\\%s 的大小失败：%v", keyPath, name, syscall.Errno(ret))
	}
	if size == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ = procRegQueryValueExW.Call(
		h,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != errorSuccess {
		return 0, nil, fmt.Errorf("winreg: 读取 %s\\%s 失败：%v", keyPath, name, syscall.Errno(ret))
	}
	if int(size) > len(buf) {
		size = uint32(len(buf))
	}
	return typ, buf[:size], nil
}

// SetString writes a REG_SZ value.
func SetString(keyPath, name, value string) error {
	h, err := openKey(keyPath, keySetValue, true)
	if err != nil {
		return err
	}
	defer closeKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winreg: %v", err)
	}
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return fmt.Errorf("winreg: %v", err)
	}
	ret, _, _ := procRegSetValueExW.Call(
		h,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		regSZ,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)*2),
	)
	if ret != errorSuccess {
		return fmt.Errorf("winreg: 写入 %s\\%s 失败：%v", keyPath, name, syscall.Errno(ret))
	}
	return nil
}

// SetDWORD writes a REG_DWORD value.
func SetDWORD(keyPath, name string, value uint32) error {
	h, err := openKey(keyPath, keySetValue, true)
	if err != nil {
		return err
	}
	defer closeKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winreg: %v", err)
	}
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	ret, _, _ := procRegSetValueExW.Call(
		h,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		regDWORD,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
	)
	if ret != errorSuccess {
		return fmt.Errorf("winreg: 写入 %s\\%s 失败：%v", keyPath, name, syscall.Errno(ret))
	}
	return nil
}

// GetString reads a string value; a REG_DWORD is rendered as its decimal form.
func GetString(keyPath, name string) (string, error) {
	typ, data, err := readValue(keyPath, name)
	if err != nil {
		return "", err
	}
	switch typ {
	case regSZ, regExpandSZ:
		return decodeUTF16(data), nil
	case regDWORD:
		if len(data) >= 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data)), 10), nil
		}
	}
	return "", fmt.Errorf("winreg: %s\\%s 的类型 %d 不是字符串", keyPath, name, typ)
}

// GetDWORD reads a numeric value; a REG_SZ holding a number is accepted too,
// because some legacy tooling stores the proxy switch that way.
func GetDWORD(keyPath, name string) (uint32, error) {
	typ, data, err := readValue(keyPath, name)
	if err != nil {
		return 0, err
	}
	switch typ {
	case regDWORD:
		if len(data) >= 4 {
			return binary.LittleEndian.Uint32(data), nil
		}
		return 0, nil
	case regSZ, regExpandSZ:
		s := strings.TrimSpace(decodeUTF16(data))
		if s == "" {
			return 0, nil
		}
		v, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return 0, fmt.Errorf("winreg: %s\\%s 的值 %q 不是数字", keyPath, name, s)
		}
		return uint32(v), nil
	}
	return 0, fmt.Errorf("winreg: %s\\%s 的类型 %d 不是 DWORD", keyPath, name, typ)
}

// DeleteValue removes a value; a value that is not there reports ErrNotFound.
func DeleteValue(keyPath, name string) error {
	h, err := openKey(keyPath, keySetValue, false)
	if err != nil {
		return err
	}
	defer closeKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winreg: %v", err)
	}
	ret, _, _ := procRegDeleteValueW.Call(h, uintptr(unsafe.Pointer(namePtr)))
	if ret == errorFileNotFound {
		return ErrNotFound
	}
	if ret != errorSuccess {
		return fmt.Errorf("winreg: 删除 %s\\%s 失败：%v", keyPath, name, syscall.Errno(ret))
	}
	return nil
}

// DeleteKey removes a key together with every value and subkey under it. The
// client never deletes a key it did not create; this exists so a test can put
// the package on a scratch key and leave no trace behind. A key that is not
// there reports ErrNotFound, matching DeleteValue.
func DeleteKey(keyPath string) error {
	sub, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return fmt.Errorf("winreg: %v", err)
	}
	ret, _, _ := procRegDeleteTreeW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)))
	if ret == errorFileNotFound {
		return ErrNotFound
	}
	if ret != errorSuccess {
		return fmt.Errorf("winreg: 删除键 %s 失败：%v", keyPath, syscall.Errno(ret))
	}
	return nil
}

// decodeUTF16 turns UTF-16LE bytes into a Go string, stopping at the
// terminator when the value carries one.
func decodeUTF16(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return syscall.UTF16ToString(u)
}
