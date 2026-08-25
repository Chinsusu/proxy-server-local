//go:build !linux

package forwarder

import (
	"errors"
	"net"
)

func OriginalDestination(*net.TCPConn) (*net.TCPAddr, error) {
	return nil, errors.New("transparent original destination requires Linux")
}
