//go:build windows

package agent

// Windows does not provide fsync semantics for directory handles. PGW's
// durable LKG/runtime publisher is a Linux production component; Windows is a
// supported build and unit-test target only.
func syncDirectory(string) error { return nil }
