//go:build windows

package secret

// Windows cannot supply the Linux dirfd/O_NOFOLLOW and ownership guarantees
// used by the installer helper, so the file mode fails closed.
func LoadRootOwnedAdminPasswordFile(string, int64) ([]byte, error) {
	return nil, ErrACLUnsupported
}
