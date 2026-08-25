//go:build windows

package sqlite

import "fmt"

func copySourceNofollow(string, string) error {
	return fmt.Errorf("sqlite: secure persistent restore source is unsupported on Windows")
}
