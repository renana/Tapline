//go:build linux

package main

import (
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

func originalDst(c net.Conn) *net.TCPAddr {
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return nil
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil
	}
	var out *net.TCPAddr
	_ = rc.Control(func(fd uintptr) {
		var sa syscall.RawSockaddrInet4
		n := uint32(unsafe.Sizeof(sa))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa)),
			uintptr(unsafe.Pointer(&n)),
			0,
		)
		if errno != 0 || sa.Family != syscall.AF_INET {
			return
		}
		port := int(sa.Port>>8 | sa.Port<<8)
		if port == 0 {
			return
		}
		out = &net.TCPAddr{
			IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
			Port: port,
		}
	})
	return out
}
