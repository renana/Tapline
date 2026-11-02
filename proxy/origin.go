package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func runOrigin(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = handleOrigin(c)
		}(c)
	}
}

func handleOrigin(c net.Conn) error {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 16384)
	n, err := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n == 0 {
		return err
	}
	head := buf[:n]
	if looksHTTP(head) {
		return originHTTP(c, head)
	}
	if _, err := c.Write(head); err != nil {
		return err
	}
	_, _ = io.Copy(c, c)
	return nil
}

func looksHTTP(b []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func originHTTP(c net.Conn, head []byte) error {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	fields := strings.Fields(string(bytes.TrimSpace(line)))
	method, path := "GET", "/"
	if len(fields) >= 1 {
		method = fields[0]
	}
	if len(fields) >= 2 {
		path = fields[1]
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
	}
	if path == "/slow" {
		time.Sleep(40 * time.Millisecond)
	}
	status, body := 200, `{"ok":true,"service":"envoy-standin"}`
	switch method + " " + path {
	case "GET /", "GET /health":
	case "GET /users":
		body = `[{"id":1,"name":"Ada Lovelace"},{"id":2,"name":"Alan Turing"}]`
	case "GET /users/2":
		body = `{"id":2,"name":"Alan Turing"}`
	case "POST /users":
		status, body = 201, `{"id":3,"created":true}`
	case "GET /error":
		status, body = 500, `{"error":"origin_fault"}`
	case "GET /status/401":
		status, body = 401, `{"status":401}`
	case "GET /headers":
		body = `{"via":"tapline"}`
	default:
		if method == "GET" && path == "/health" {
			break
		}
		status = 404
		body = fmt.Sprintf(`{"error":"not_found","path":"%s"}`, path)
	}
	reason := "OK"
	switch status {
	case 201:
		reason = "Created"
	case 401:
		reason = "Unauthorized"
	case 404:
		reason = "Not Found"
	case 500:
		reason = "Internal Server Error"
	}
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n%s",
		status, reason, len(body), body,
	)
	_, err := io.WriteString(c, resp)
	return err
}
