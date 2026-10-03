package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/sysproxy"
)

// The system proxy is a machine-wide setting, and a killed process runs no
// cleanup at all. The guard exists for that one case: a second, invisible copy
// of this exe whose only job is to outlive the client and put the setting back.
//
// It returns from main before a window, a tray icon or a console server exists,
// so it can never flash anything on screen and can never hold a port.
func superviseProxyGuard(ctx context.Context, a *app.App, cfgPath string) {
	var running *exec.Cmd
	var startedAt time.Time
	// A guard that dies the moment it starts has nothing to guard. Without a
	// brake this loop would launch a copy of this exe on every tick, forever:
	// that is the churn a user sees as the client "opening something" over and
	// over, and it is why the ownership check below is the gate, not the
	// registry switch.
	shortRuns := 0
	var cooldownUntil time.Time

	stop := func() {
		if running == nil || running.Process == nil {
			running = nil
			a.SetProxyGuardRunning(false)
			return
		}
		_ = running.Process.Kill()
		_, _ = running.Process.Wait()
		running = nil
		// The settings card shows whether the guard is alive right now, so
		// the state has to be cleared on every path out of here.
		a.SetProxyGuardRunning(false)
	}
	defer stop()

	const (
		tick        = 2 * time.Second
		shortLife   = 1500 * time.Millisecond
		maxShortRun = 3
		cooldown    = 5 * time.Minute
	)

	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// Ownership decides whether there is a job here, not "the switch is
		// up". On a machine where another client owns the system proxy the
		// registry says 1 while this client has written nothing at all - that
		// is a normal state, not a reason to start a guard.
		if !sysproxy.OwnedBy(sysproxy.StatePath(), os.Getpid()) {
			stop()
			continue
		}
		if running != nil && running.Process != nil && sysproxy.OwnerAlive(running.Process.Pid) {
			continue
		}
		if running != nil {
			if time.Since(startedAt) < shortLife {
				shortRuns++
			} else {
				shortRuns = 0
			}
			running = nil
			if shortRuns >= maxShortRun {
				a.Logf("系统代理守护进程连续 %d 次立即退出，暂停 %s 后再试", shortRuns, cooldown)
				cooldownUntil = time.Now().Add(cooldown)
				shortRuns = 0
			}
		}
		if time.Now().Before(cooldownUntil) {
			continue
		}
		exe, err := os.Executable()
		if err != nil {
			continue
		}
		cmd := exec.Command(exe, "-proxy-guard", strconv.Itoa(os.Getpid()), "-config", cfgPath)
		hideWindow(cmd)
		if err := cmd.Start(); err != nil {
			continue
		}
		running = cmd
		startedAt = time.Now()
		a.SetProxyGuardRunning(true)
		a.Logf("系统代理守护进程已启动 pid=%d", cmd.Process.Pid)
	}
}

// runProxyGuard is the guard's whole program: wait for the client to disappear,
// then undo the system proxy if it is still ours. The client restores the
// setting itself on a normal exit, so finding no snapshot here means "nothing
// to do", not "something went wrong".
func runProxyGuard(ownerPID int) {
	for {
		if sysproxy.WaitForExit(ownerPID, 500*time.Millisecond) {
			break
		}
		if _, ok := sysproxy.LoadSnapshot(sysproxy.StatePath()); !ok {
			return
		}
	}
	restored, err := sysproxy.Restore()
	if err != nil {
		fmt.Println("proxy-guard: 还原系统代理失败：", err)
		return
	}
	if restored {
		fmt.Println("proxy-guard: 客户端已退出，系统代理已还原")
	}
}
