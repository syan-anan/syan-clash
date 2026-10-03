package winsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// skipNonWindows keeps the suite green on Linux/macOS: the SCM is Windows only.
func skipNonWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows 服务控制管理器只在 Windows 上存在")
	}
}

// labServiceName builds a name that cannot collide with a real local service,
// so the tests never touch anything installed on this machine.
func labServiceName() string {
	return fmt.Sprintf("syan-clash-lab-does-not-exist-%d-%d", os.Getpid(), time.Now().UnixNano())
}

func TestStateLabels(t *testing.T) {
	// State 的数值必须与 Win32 SERVICE_STATUS.dwCurrentState 一致：
	// 上报状态时是按数值直接转发的。
	values := map[State]uint32{
		StateUnknown:         0,
		StateStopped:         1,
		StateStartPending:    2,
		StateStopPending:     3,
		StateRunning:         4,
		StateContinuePending: 5,
		StatePausePending:    6,
		StatePaused:          7,
	}
	names := make(map[string]State, len(values))
	labels := make(map[string]State, len(values))
	for state, want := range values {
		if uint32(state) != want {
			t.Fatalf("State(%d) 的数值应为 %d", uint32(state), want)
		}
		name := state.String()
		if name == "" {
			t.Fatalf("State(%d).String() 返回空字符串", uint32(state))
		}
		label := state.Label()
		if label == "" {
			t.Fatalf("State(%d).Label() 返回空字符串", uint32(state))
		}
		if prev, ok := names[name]; ok {
			t.Fatalf("State.String() 重复：State(%d) 与 State(%d) 都返回 %q", uint32(prev), uint32(state), name)
		}
		if prev, ok := labels[label]; ok {
			t.Fatalf("State.Label() 重复：State(%d) 与 State(%d) 都返回 %q", uint32(prev), uint32(state), label)
		}
		names[name] = state
		labels[label] = state
	}
}

func TestQueryMissingService(t *testing.T) {
	skipNonWindows(t)

	name := labServiceName()
	st, err := Query(name)
	if err != nil {
		t.Fatalf("查询不存在的服务 %s 不应该报错，实际：%v", name, err)
	}
	if st.Installed {
		t.Fatalf("服务 %s 不该存在，实际 Installed=true", name)
	}
	if st.State != StateUnknown {
		t.Fatalf("未安装的服务 State 应为 unknown，实际 %s", st.State)
	}
}

func TestUninstallMissingServiceIsIdempotent(t *testing.T) {
	skipNonWindows(t)

	name := labServiceName()
	if err := Uninstall(name); err != nil {
		t.Fatalf("卸载不存在的服务 %s 应该返回 nil，实际：%v", name, err)
	}
}

func TestDispatchOutsideService(t *testing.T) {
	skipNonWindows(t)

	done := make(chan error, 1)
	go func() {
		done <- Dispatch(Handler{
			Name: "syan-clash-lab-not-a-service",
			Run: func(ctx context.Context, report func(State, string)) error {
				report(StateRunning, "普通进程里不该跑到这里")
				return nil
			},
		})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNotService) {
			t.Fatalf("普通进程里 Dispatch 应返回 ErrNotService，实际：%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Dispatch 在普通进程里挂住了：3 秒内没有返回 ErrNotService")
	}
}

func TestStopMissingServiceReturnsNotInstalled(t *testing.T) {
	skipNonWindows(t)

	name := labServiceName()
	err := Stop(name)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("停止不存在的服务应返回 ErrNotInstalled，实际：%v", err)
	}
}
