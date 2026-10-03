//go:build !windows

package winsvc

// Dispatch has no SCM to talk to outside Windows.
func Dispatch(h Handler) error {
	return ErrUnsupported
}
