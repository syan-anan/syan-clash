//go:build windows

package winsvc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
)

// serviceTableEntry is SERVICE_TABLE_ENTRYW: 2 pointers = 16 bytes.
type serviceTableEntry struct {
	ServiceName *uint16
	ServiceProc uintptr
}

// One dispatcher per process; the SCM calls ServiceMain on its own thread, so
// the handler and the runtime are handed over under a mutex.
var (
	dispatchMu      sync.Mutex
	dispatchHandler *Handler
	dispatchNamePtr *uint16
	dispatchRunning bool
	dispatchRunErr  error
)

var (
	runtimeMu     sync.Mutex
	activeRuntime *serviceRuntime
)

// serviceRuntime carries the status handle the SCM control handler (another
// thread) shares with the service body.
type serviceRuntime struct {
	handle  syscall.Handle
	mu      sync.Mutex
	cancel  context.CancelFunc
	current State
}

// requestStop cancels the service context; the control handler thread calls it.
func (rt *serviceRuntime) requestStop() {
	rt.mu.Lock()
	cancel := rt.cancel
	rt.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// report publishes a state change to the SCM. The message has no slot in
// SERVICE_STATUS, it only carries intent for readers of this code.
func (rt *serviceRuntime) report(state State, msg string) {
	rt.reportExit(state, 0, 0)
}

// reportExit is report plus the Win32 exit code fields.
func (rt *serviceRuntime) reportExit(state State, win32Exit uint32, specific uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.current = state
	if rt.handle == 0 {
		return
	}
	ss := serviceStatus{
		ServiceType:             serviceWin32OwnProcess,
		CurrentState:            uint32(state),
		Win32ExitCode:           win32Exit,
		ServiceSpecificExitCode: specific,
	}
	switch state {
	case StateRunning:
		ss.ControlsAccepted = serviceAcceptStop | serviceAcceptShutdown
	case StateStartPending, StateStopPending:
		ss.CheckPoint = 1
		ss.WaitHint = 5000
	}
	_, _, _ = procSetServiceStatus.Call(uintptr(rt.handle), uintptr(unsafe.Pointer(&ss)))
}

// reportCurrent re-publishes the current state (SERVICE_CONTROL_INTERROGATE).
func (rt *serviceRuntime) reportCurrent() {
	rt.mu.Lock()
	state := rt.current
	rt.mu.Unlock()
	rt.report(state, "")
}

// serviceCtrlHandlerEx is the HandlerEx callback, called by the SCM on its own
// thread - hence the mutex around every status write.
func serviceCtrlHandlerEx(ctrl uint32, eventType uint32, eventData uintptr, eventContext uintptr) uintptr {
	runtimeMu.Lock()
	rt := activeRuntime
	runtimeMu.Unlock()
	if rt == nil {
		return 0
	}
	switch ctrl {
	case serviceControlStop:
		rt.report(StateStopPending, "收到停止请求")
		rt.requestStop()
	case serviceControlShutdown:
		rt.report(StateStopPending, "系统正在关机")
		rt.requestStop()
	case serviceControlInterrogate:
		rt.reportCurrent()
	default:
		// PARAMCHANGE / NETBINDCHANGE / PAUSE / CONTINUE 等一律不支持。
	}
	return 0
}

// serviceMain is the ServiceMain entry point the SCM invokes on its own thread.
func serviceMain(argc uint32, argv **uint16) uintptr {
	dispatchMu.Lock()
	h := dispatchHandler
	namePtr := dispatchNamePtr
	dispatchMu.Unlock()
	if h == nil || namePtr == nil {
		return 0
	}

	handle, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		syscall.NewCallback(serviceCtrlHandlerEx),
		0, // lpContext
	)
	if handle == 0 {
		return 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt := &serviceRuntime{
		handle:  syscall.Handle(handle),
		cancel:  cancel,
		current: StateStartPending,
	}
	runtimeMu.Lock()
	activeRuntime = rt
	runtimeMu.Unlock()
	defer func() {
		runtimeMu.Lock()
		if activeRuntime == rt {
			activeRuntime = nil
		}
		runtimeMu.Unlock()
	}()

	rt.report(StateStartPending, "正在启动")
	rt.report(StateRunning, "已就绪")

	// 服务主体跑在普通 goroutine 里，serviceMain 只等它结束；这样控制回调
	// 里的 cancel 能立刻生效，也不会把回调线程拖进长时间阻塞。
	done := make(chan error, 1)
	go func() {
		done <- h.Run(ctx, rt.report)
	}()
	runErr := <-done

	if runErr != nil {
		rt.reportExit(StateStopped, errServiceSpecificError, 1)
	} else {
		rt.reportExit(StateStopped, 0, 0)
	}

	dispatchMu.Lock()
	dispatchRunErr = runErr
	dispatchMu.Unlock()
	return 0
}

// Dispatch hands this process to the SCM through StartServiceCtrlDispatcherW.
// It blocks until every hosted service has stopped. When the process was not
// started by the SCM (plain console run) it returns ErrNotService instead of
// hanging.
func Dispatch(h Handler) error {
	name := strings.TrimSpace(h.Name)
	if name == "" {
		return fmt.Errorf("winsvc: Dispatch 的服务名不能为空")
	}
	if h.Run == nil {
		return fmt.Errorf("winsvc: Dispatch 的 Handler.Run 不能为空")
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winsvc: 服务名 %q 无法转换为 UTF-16：%v", name, err)
	}

	dispatchMu.Lock()
	if dispatchRunning {
		dispatchMu.Unlock()
		return fmt.Errorf("winsvc: 本进程已经有一个服务宿主在运行")
	}
	dispatchRunning = true
	dispatchHandler = &h
	dispatchNamePtr = namePtr
	dispatchRunErr = nil
	dispatchMu.Unlock()

	defer func() {
		dispatchMu.Lock()
		dispatchRunning = false
		dispatchHandler = nil
		dispatchNamePtr = nil
		dispatchMu.Unlock()
	}()

	table := [2]serviceTableEntry{
		{ServiceName: namePtr, ServiceProc: syscall.NewCallback(serviceMain)},
		{ServiceName: nil, ServiceProc: 0},
	}
	r1, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r1 == 0 {
		// 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT：不是由 SCM 启动的。
		// 控制台进程直接调用就是这个结果，必须立刻返回，不能挂住。
		if code := codeOf(callErr); code == errFailedServiceControllerConnect || code == 0 {
			return ErrNotService
		}
		return win32Error("StartServiceCtrlDispatcherW", callErr)
	}

	dispatchMu.Lock()
	runErr := dispatchRunErr
	dispatchMu.Unlock()
	if runErr != nil {
		return fmt.Errorf("winsvc: 服务 %s 的主体返回错误：%w", name, runErr)
	}
	return nil
}
