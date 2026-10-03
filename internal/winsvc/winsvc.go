// Package winsvc implements the Windows Service Control Manager (SCM) client
// side and a service dispatcher host directly on advapi32.
//
// It follows the same rules as internal/winreg: standard library only
// (syscall/unsafe, never golang.org/x/sys), no shelling out, no console window
// and no popup - only advapi32 calls, memory access and returned errors. Every
// Win32 failure comes back as a Chinese error carrying the numeric Win32 error
// code.
//
// The platform independent declarations live in this file. The Windows
// implementations are in scm_windows.go and host_windows.go; the stubs for the
// other platforms are in scm_other.go and host_other.go.
package winsvc

import (
	"context"
	"errors"
)

// DefaultName is the production service name.
const DefaultName = "syan-clash-service"

// State mirrors SERVICE_STATUS.dwCurrentState. The numeric values are part of
// the ABI: they are forwarded to SetServiceStatus unchanged.
type State uint32

const (
	StateUnknown         State = 0
	StateStopped         State = 1
	StateStartPending    State = 2
	StateStopPending     State = 3
	StateRunning         State = 4
	StateContinuePending State = 5
	StatePausePending    State = 6
	StatePaused          State = 7
)

// String returns the English name ("stopped" / "running" / ...).
func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStartPending:
		return "start-pending"
	case StateStopPending:
		return "stop-pending"
	case StateRunning:
		return "running"
	case StateContinuePending:
		return "continue-pending"
	case StatePausePending:
		return "pause-pending"
	case StatePaused:
		return "paused"
	default:
		return "unknown"
	}
}

// Label returns the Chinese name the UI shows ("未运行" / "运行中" / ...).
func (s State) Label() string {
	switch s {
	case StateStopped:
		return "未运行"
	case StateStartPending:
		return "启动中"
	case StateStopPending:
		return "停止中"
	case StateRunning:
		return "运行中"
	case StateContinuePending:
		return "恢复中"
	case StatePausePending:
		return "暂停中"
	case StatePaused:
		return "已暂停"
	default:
		return "未知"
	}
}

// Status is a snapshot of one service query.
type Status struct {
	Name        string
	Installed   bool
	State       State
	PID         uint32
	BinPath     string
	DisplayName string
	AutoStart   bool
	Account     string
}

// InstallConfig describes the service to create.
type InstallConfig struct {
	Name        string
	DisplayName string
	Description string

	// BinPath 是完整的服务命令行，调用方负责给 exe 路径加引号，
	// 例如："C:\Apps\syan-clash\syan-clash.exe" -service -config "C:\Apps\syan-clash\config.json"
	// Install 把它原样写进 lpBinaryPathName，不做任何引号加工
	// （再包一层引号会变成 ""C:\Apps\syan-clash\syan-clash.exe" -service ..."，
	// 服务启动时会直接失败）。
	BinPath string

	// Account 为空表示 LocalSystem。
	Account string

	// AutoStart 为 true 用 SERVICE_AUTO_START，否则用 SERVICE_DEMAND_START。
	AutoStart bool
}

var (
	// ErrExists reports a service that is already installed.
	ErrExists = errors.New("服务已经安装")
	// ErrNotInstalled reports a service that is not installed.
	ErrNotInstalled = errors.New("服务没有安装")
	// ErrUnsupported reports the non-Windows stubs.
	ErrUnsupported = errors.New("当前平台不支持 Windows 服务")
	// ErrNotService reports a process that the SCM did not start.
	ErrNotService = errors.New("当前进程不是由服务控制管理器启动的")
)

// Handler describes one service body.
type Handler struct {
	Name string

	// Run is the service body. ctx is cancelled when the SCM sends
	// STOP or SHUTDOWN; report publishes start-pending / running / stop-pending.
	Run func(ctx context.Context, report func(State, string)) error
}
