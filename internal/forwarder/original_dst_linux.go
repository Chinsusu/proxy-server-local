//go:build linux

package forwarder

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

func OriginalDestination(conn *net.TCPConn) (*net.TCPAddr, error) {
	var address syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(address))
	var socketErr error
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	err = rawConn.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.SOL_IP), uintptr(soOriginalDst), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			socketErr = errno
		}
	})
	if err != nil {
		return nil, err
	}
	if socketErr != nil {
		return nil, socketErr
	}
	ip := net.IPv4(address.Addr[0], address.Addr[1], address.Addr[2], address.Addr[3])
	port := int(binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&address.Port)))[:]))
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
