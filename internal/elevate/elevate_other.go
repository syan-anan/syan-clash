//go:build !windows

package elevate

// IsElevated reports whether the process runs with root privileges.
func IsElevated() bool { return true }

// CanCreateTun reports TUN availability on this platform.
func CanCreateTun() (bool, string) {
	return true, "非 Windows 平台；TUN 权限取决于运行用户"
}

// Elevate is not needed outside Windows.
func Elevate(executable string, args []string) error { return nil }
