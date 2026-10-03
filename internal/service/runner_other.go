//go:build !windows

package service

import "syscall"

// sysProcAttr 在非 Windows 平台没有对应语义，返回 nil 让 os/exec 走默认路径。
func sysProcAttr() *syscall.SysProcAttr { return nil }
