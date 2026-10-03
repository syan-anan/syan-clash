//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Win32 constants (winsvc.h).
const (
	scManagerConnect       = 0x0001
	scManagerCreateService = 0x0002
	scManagerAllAccess     = 0xF003F

	serviceQueryConfig = 0x0001
	serviceQueryStatus = 0x0004
	serviceStart       = 0x0010
	serviceStop        = 0x0020
	serviceAllAccess   = 0xF01FF

	serviceWin32OwnProcess = 0x00000010
	serviceAutoStart       = 0x00000002
	serviceDemandStart     = 0x00000003
	serviceErrorNormal     = 0x00000001

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005
	serviceAcceptStop         = 0x00000001
	serviceAcceptShutdown     = 0x00000004

	serviceStopped         = 0x00000001
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004
	serviceContinuePending = 0x00000005
	servicePausePending    = 0x00000006
	servicePaused          = 0x00000007

	scStatusProcessInfo      = 0
	serviceConfigDescription = 1

	errInsufficientBuffer             = 122
	errServiceAlreadyRunning          = 1056
	errServiceDoesNotExist            = 1060
	errServiceNotActive               = 1062
	errServiceSpecificError           = 1066
	errServiceExists                  = 1073
	errFailedServiceControllerConnect = 1063
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenSCManagerW        = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW        = advapi32.NewProc("CreateServiceW")
	procOpenServiceW          = advapi32.NewProc("OpenServiceW")
	procDeleteService         = advapi32.NewProc("DeleteService")
	procStartServiceW         = advapi32.NewProc("StartServiceW")
	procControlService        = advapi32.NewProc("ControlService")
	procQueryServiceStatusEx  = advapi32.NewProc("QueryServiceStatusEx")
	procQueryServiceConfigW   = advapi32.NewProc("QueryServiceConfigW")
	procChangeServiceConfig2W = advapi32.NewProc("ChangeServiceConfig2W")
	procCloseServiceHandle    = advapi32.NewProc("CloseServiceHandle")
)

// serviceStatus is SERVICE_STATUS: 7 DWORDs = 28 bytes.
type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// serviceStatusProcess is SERVICE_STATUS_PROCESS: 9 DWORDs = 36 bytes.
type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

// queryServiceConfig is QUERY_SERVICE_CONFIGW.
type queryServiceConfig struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagID            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

// serviceDescription is SERVICE_DESCRIPTIONW.
type serviceDescription struct {
	Description *uint16
}

// codeOf extracts the numeric Win32 error code from the error returned by Call.
func codeOf(err error) uint32 {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return uint32(e)
	}
	return 0
}

// win32Error formats a failed Win32 call together with its numeric error code.
func win32Error(op string, err error) error {
	if err == nil {
		return fmt.Errorf("winsvc: %s 失败，但 Win32 没有返回错误码", op)
	}
	if code := codeOf(err); code != 0 {
		return fmt.Errorf("winsvc: %s 失败：Win32 错误 %d：%v", op, code, err)
	}
	return fmt.Errorf("winsvc: %s 失败：%v", op, err)
}

func openSCManager(access uint32) (syscall.Handle, error) {
	h, _, callErr := procOpenSCManagerW.Call(0, 0, uintptr(access))
	if h == 0 {
		return 0, win32Error("OpenSCManagerW", callErr)
	}
	return syscall.Handle(h), nil
}

// openService opens an existing service. A missing service maps to
// ErrNotInstalled so callers can treat "not there" as a normal state.
func openService(scm syscall.Handle, name string, access uint32) (syscall.Handle, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("winsvc: 服务名 %q 无法转换为 UTF-16：%v", name, err)
	}
	h, _, callErr := procOpenServiceW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(access),
	)
	if h == 0 {
		if codeOf(callErr) == errServiceDoesNotExist {
			return 0, ErrNotInstalled
		}
		return 0, win32Error("OpenServiceW("+name+")", callErr)
	}
	return syscall.Handle(h), nil
}

func closeServiceHandle(h syscall.Handle) {
	if h == 0 {
		return
	}
	_, _, _ = procCloseServiceHandle.Call(uintptr(h))
}

// utf16PtrToString reads a NUL terminated UTF-16 string out of a Win32 buffer.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	const maxChars = 1 << 15
	buf := unsafe.Slice(p, maxChars)
	for i, c := range buf {
		if c == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

func queryServiceStatus(hSvc syscall.Handle) (serviceStatusProcess, error) {
	var ssp serviceStatusProcess
	var needed uint32
	r1, _, callErr := procQueryServiceStatusEx.Call(
		uintptr(hSvc),
		uintptr(scStatusProcessInfo),
		uintptr(unsafe.Pointer(&ssp)),
		unsafe.Sizeof(ssp),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return serviceStatusProcess{}, win32Error("QueryServiceStatusEx", callErr)
	}
	return ssp, nil
}

type serviceConfigInfo struct {
	binPath     string
	displayName string
	account     string
	startType   uint32
}

// readServiceConfig runs the two phase QueryServiceConfigW call: ask for the
// size first (ERROR_INSUFFICIENT_BUFFER), then read the buffer.
func readServiceConfig(hSvc syscall.Handle) (serviceConfigInfo, error) {
	var needed uint32
	r1, _, callErr := procQueryServiceConfigW.Call(
		uintptr(hSvc),
		0, // lpServiceConfig: NULL asks for the required size
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 && codeOf(callErr) != errInsufficientBuffer {
		return serviceConfigInfo{}, win32Error("QueryServiceConfigW(询问缓冲区大小)", callErr)
	}
	if needed == 0 {
		return serviceConfigInfo{}, fmt.Errorf("winsvc: QueryServiceConfigW 返回的缓冲区大小为 0")
	}

	buf := make([]byte, needed)
	r1, _, callErr = procQueryServiceConfigW.Call(
		uintptr(hSvc),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return serviceConfigInfo{}, win32Error("QueryServiceConfigW", callErr)
	}

	cfg := (*queryServiceConfig)(unsafe.Pointer(&buf[0]))
	return serviceConfigInfo{
		binPath:     utf16PtrToString(cfg.BinaryPathName),
		displayName: utf16PtrToString(cfg.DisplayName),
		account:     utf16PtrToString(cfg.ServiceStartName),
		startType:   cfg.StartType,
	}, nil
}

// Query reports the current status of a service. A service that is not
// installed is a normal state, not an error: Installed is false and err is nil.
func Query(name string) (Status, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Status{}, fmt.Errorf("winsvc: Query 的服务名不能为空")
	}

	scm, err := openSCManager(scManagerConnect)
	if err != nil {
		return Status{}, err
	}
	defer closeServiceHandle(scm)

	hSvc, err := openService(scm, name, serviceQueryStatus|serviceQueryConfig)
	if err != nil {
		if errors.Is(err, ErrNotInstalled) {
			return Status{Name: name, Installed: false, State: StateUnknown}, nil
		}
		return Status{}, err
	}
	defer closeServiceHandle(hSvc)

	ssp, err := queryServiceStatus(hSvc)
	if err != nil {
		return Status{Name: name, Installed: true}, err
	}
	st := Status{
		Name:      name,
		Installed: true,
		State:     State(ssp.CurrentState),
		PID:       ssp.ProcessID,
	}

	cfg, err := readServiceConfig(hSvc)
	if err != nil {
		return st, err
	}
	st.BinPath = cfg.binPath
	st.DisplayName = cfg.displayName
	st.Account = cfg.account
	st.AutoStart = cfg.startType == serviceAutoStart
	return st, nil
}

// Install creates the service. When a service with the same name already exists
// it returns ErrExists and leaves the existing service untouched.
func Install(cfg InstallConfig) error {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return fmt.Errorf("winsvc: Install 的服务名不能为空")
	}
	// BinPath 是调用方给的完整命令行（引号由调用方给），原样写入。
	binPath := strings.TrimSpace(cfg.BinPath)
	if binPath == "" {
		return fmt.Errorf("winsvc: Install 的服务命令行（BinPath）不能为空")
	}
	displayName := strings.TrimSpace(cfg.DisplayName)
	if displayName == "" {
		displayName = name
	}
	account := strings.TrimSpace(cfg.Account)

	scm, err := openSCManager(scManagerCreateService)
	if err != nil {
		return err
	}
	defer closeServiceHandle(scm)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winsvc: 服务名 %q 无法转换为 UTF-16：%v", name, err)
	}
	displayPtr, err := syscall.UTF16PtrFromString(displayName)
	if err != nil {
		return fmt.Errorf("winsvc: 显示名 %q 无法转换为 UTF-16：%v", displayName, err)
	}
	binPtr, err := syscall.UTF16PtrFromString(binPath)
	if err != nil {
		return fmt.Errorf("winsvc: 服务命令行无法转换为 UTF-16：%v", err)
	}
	var accountPtr *uint16
	if account != "" {
		accountPtr, err = syscall.UTF16PtrFromString(account)
		if err != nil {
			return fmt.Errorf("winsvc: 账户 %q 无法转换为 UTF-16：%v", account, err)
		}
	}

	startType := uintptr(serviceDemandStart)
	if cfg.AutoStart {
		startType = serviceAutoStart
	}

	hSvc, _, callErr := procCreateServiceW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(displayPtr)),
		uintptr(serviceAllAccess),
		uintptr(serviceWin32OwnProcess),
		startType,
		uintptr(serviceErrorNormal),
		uintptr(unsafe.Pointer(binPtr)),
		0, // lpLoadOrderGroup
		0, // lpdwTagId
		0, // lpDependencies
		uintptr(unsafe.Pointer(accountPtr)),
		0, // lpPassword
	)
	if hSvc == 0 {
		if codeOf(callErr) == errServiceExists {
			return ErrExists
		}
		return win32Error("CreateServiceW("+name+")", callErr)
	}
	defer closeServiceHandle(syscall.Handle(hSvc))

	// 描述只能用 ChangeServiceConfig2W + SERVICE_CONFIG_DESCRIPTION 写，
	// ChangeServiceConfigW 没有描述参数。写描述失败不影响服务本身，忽略。
	if desc := strings.TrimSpace(cfg.Description); desc != "" {
		if descPtr, derr := syscall.UTF16PtrFromString(desc); derr == nil {
			sd := serviceDescription{Description: descPtr}
			_, _, _ = procChangeServiceConfig2W.Call(
				uintptr(hSvc),
				uintptr(serviceConfigDescription),
				uintptr(unsafe.Pointer(&sd)),
			)
		}
	}
	return nil
}

// deleteService removes an installed service. A service that vanished in the
// meantime is not an error.
func deleteService(name string) error {
	scm, err := openSCManager(scManagerConnect)
	if err != nil {
		return err
	}
	defer closeServiceHandle(scm)

	hSvc, err := openService(scm, name, serviceAllAccess)
	if err != nil {
		if errors.Is(err, ErrNotInstalled) {
			return nil
		}
		return err
	}
	defer closeServiceHandle(hSvc)

	r1, _, callErr := procDeleteService.Call(uintptr(hSvc))
	if r1 == 0 {
		if codeOf(callErr) == errServiceDoesNotExist {
			return nil
		}
		return win32Error("DeleteService("+name+")", callErr)
	}
	return nil
}

// Uninstall stops the service (best effort) and then deletes it. It is
// idempotent: uninstalling a service that is not installed returns nil.
func Uninstall(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("winsvc: Uninstall 的服务名不能为空")
	}

	st, err := Query(name)
	if err != nil {
		return err
	}
	if !st.Installed {
		return nil
	}

	// 先尝试停止；即使停不下来也要继续尝试删除，并把停止错误一并报出来。
	stopErr := Stop(name)
	if errors.Is(stopErr, ErrNotInstalled) {
		return nil
	}

	delErr := deleteService(name)
	if delErr == nil {
		return nil
	}
	if stopErr != nil {
		return fmt.Errorf("winsvc: Uninstall(%s) 停止失败：%v；删除失败：%v", name, stopErr, delErr)
	}
	return delErr
}

// Start starts the service and waits until it reports running.
func Start(name string) error {
	st, err := Query(name)
	if err != nil {
		return err
	}
	if !st.Installed {
		return ErrNotInstalled
	}
	if st.State == StateRunning {
		return nil
	}

	scm, err := openSCManager(scManagerConnect)
	if err != nil {
		return err
	}
	defer closeServiceHandle(scm)

	hSvc, err := openService(scm, name, serviceStart|serviceQueryStatus)
	if err != nil {
		return err
	}
	defer closeServiceHandle(hSvc)

	r1, _, callErr := procStartServiceW.Call(uintptr(hSvc), 0, 0)
	if r1 == 0 {
		switch codeOf(callErr) {
		case errServiceDoesNotExist:
			return ErrNotInstalled
		case errServiceAlreadyRunning:
			return nil
		default:
			return win32Error("StartServiceW("+name+")", callErr)
		}
	}

	if _, err := WaitForState(name, StateRunning, 15*time.Second); err != nil {
		return err
	}
	return nil
}

// Stop asks the service to stop and waits until it reports stopped.
func Stop(name string) error {
	st, err := Query(name)
	if err != nil {
		return err
	}
	if !st.Installed {
		return ErrNotInstalled
	}
	if st.State == StateStopped {
		return nil
	}

	scm, err := openSCManager(scManagerConnect)
	if err != nil {
		return err
	}
	defer closeServiceHandle(scm)

	hSvc, err := openService(scm, name, serviceStop|serviceQueryStatus)
	if err != nil {
		return err
	}
	defer closeServiceHandle(hSvc)

	var ss serviceStatus
	r1, _, callErr := procControlService.Call(
		uintptr(hSvc),
		uintptr(serviceControlStop),
		uintptr(unsafe.Pointer(&ss)),
	)
	if r1 == 0 {
		switch codeOf(callErr) {
		case errServiceDoesNotExist:
			return ErrNotInstalled
		case errServiceNotActive:
			// 已经在停止或已经停止，继续等状态落地。
		default:
			return win32Error("ControlService(SERVICE_CONTROL_STOP)", callErr)
		}
	}

	if _, err := WaitForState(name, StateStopped, 15*time.Second); err != nil {
		return err
	}
	return nil
}

// WaitForState polls until the service reaches want or the timeout expires. On
// timeout it returns the last observed Status together with the error.
func WaitForState(name string, want State, timeout time.Duration) (Status, error) {
	deadline := time.Now().Add(timeout)
	var (
		last    Status
		lastErr error
	)
	for {
		st, err := Query(name)
		if err != nil {
			lastErr = err
		} else {
			last = st
			if st.State == want {
				return st, nil
			}
		}
		if !time.Now().Before(deadline) {
			if lastErr != nil {
				return last, fmt.Errorf("winsvc: WaitForState(%s) 等待 %s 超时：%v", name, want, lastErr)
			}
			return last, fmt.Errorf("winsvc: WaitForState(%s) 等待状态 %s 超时，当前 %s", name, want, last.State)
		}
		time.Sleep(150 * time.Millisecond)
	}
}
