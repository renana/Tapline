//go:build linux

package main

import (
	"net"
	"syscall"
	"unsafe"
)

func tcpKernelInfo(c net.Conn) (rttUs uint32, retrans uint32, ok bool) {
	tc, isTCP := c.(*net.TCPConn)
	if !isTCP || tc == nil {
		return 0, 0, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var info syscall.TCPInfo
	var errno syscall.Errno
	_ = rc.Control(func(fd uintptr) {
		n := uint32(unsafe.Sizeof(info))
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_TCP),
			uintptr(syscall.TCP_INFO),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&n)),
			0,
		)
	})
	if errno != 0 {
		return 0, 0, false
	}
	return info.Rtt, info.Total_retrans, true
}
