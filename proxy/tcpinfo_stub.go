//go:build !linux

package main

import "net"

func tcpKernelInfo(net.Conn) (uint32, uint32, bool) { return 0, 0, false }
