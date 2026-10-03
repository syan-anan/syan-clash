//go:build windows

package service

import "syscall"

// sysProcAttr 让子进程彻底无窗口：CREATE_NO_WINDOW 阻止系统为它分配控制台，
// HideWindow 覆盖 STARTUPINFO 的显示标志。两者都要，因为服务跑在会话 0，
// 任何可见窗口都会变成用户桌面上的幽灵弹窗。
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}
