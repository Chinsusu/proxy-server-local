//go:build !linux

package main

import "errors"

func launch(_ []string) error {
	return errors.New("production launcher is supported only on Linux")
}
