//go:build !linux

package main

import "net"

func originalDst(net.Conn) *net.TCPAddr { return nil }
