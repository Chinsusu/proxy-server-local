//go:build windows

package sqlite

// Windows ACL enforcement requires a token/ACL-aware provider. File paths used
// by this local development build retain the OS ACL; key providers fail closed.
func secureSQLiteParent(string) error   { return nil }
func secureSQLiteFile(string) error     { return nil }
func secureSQLiteSidecars(string) error { return nil }
