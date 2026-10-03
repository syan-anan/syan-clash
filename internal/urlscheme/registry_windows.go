//go:build windows

package urlscheme

import (
	"errors"
	"fmt"
	"strings"

	"vvpn/internal/winreg"
)

// Current reports what this machine currently has registered for scheme. A key
// that is missing, or that carries no open command, reports Registered=false
// rather than an error: "nobody owns this scheme" is a normal state.
func Current(scheme string) Registration {
	reg := Registration{Scheme: scheme, Key: KeyPath(scheme)}
	cmd, err := winreg.GetString(reg.Key+`\shell\open\command`, "")
	if err != nil {
		return reg
	}
	reg.Command = strings.TrimSpace(cmd)
	reg.Registered = reg.Command != ""
	if !reg.Registered {
		return reg
	}
	reg.Owner = ownerOf(reg.Command)
	reg.Ours = isOurs(reg.Owner)
	reg.Foreign = !reg.Ours
	return reg
}

// Register points the scheme at this executable. It is idempotent, and it
// refuses - without writing a single value - when the registration belongs to
// another program.
func Register(scheme, exePath string) (Registration, error) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return Registration{}, fmt.Errorf("urlscheme: 可执行文件路径为空")
	}
	cur := Current(scheme)
	if cur.Registered && cur.Foreign {
		return cur, fmt.Errorf("%w：%s", ErrForeignOwner, cur.Owner)
	}
	key := KeyPath(scheme)
	// The values are written in the order Explorer reads them: the protocol
	// marker first, then the command. A registration without the marker is
	// ignored by the shell, so writing it last would leave a window in which
	// the scheme exists but does nothing.
	if err := winreg.SetString(key, "URL Protocol", ""); err != nil {
		return cur, err
	}
	if err := winreg.SetString(key, "", "URL:"+scheme); err != nil {
		return cur, err
	}
	if err := winreg.SetString(key+`\shell\open\command`, "", Command(exePath)); err != nil {
		return cur, err
	}
	return Current(scheme), nil
}

// Unregister removes the registration, but only when it is this program's.
// Deleting somebody else's would be the same hijack in the other direction.
func Unregister(scheme string) error {
	cur := Current(scheme)
	if !cur.Registered {
		return nil
	}
	if cur.Foreign {
		return fmt.Errorf("%w：%s", ErrForeignOwner, cur.Owner)
	}
	if err := winreg.DeleteKey(KeyPath(scheme)); err != nil && !errors.Is(err, winreg.ErrNotFound) {
		return err
	}
	return nil
}
