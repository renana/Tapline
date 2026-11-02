package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type hop int

const (
	hopInbound hop = iota
	hopOutbound
)

func main() {
	inbound := env("TAPLINE_INBOUND", env("TAPLINE_LISTEN", "0.0.0.0:15000"))
	app := env("TAPLINE_APP", env("TAPLINE_ENVOY", "127.0.0.1:15001"))
	outbound := env("TAPLINE_OUTBOUND", "0.0.0.0:15005")
	adminAddr := env("TAPLINE_ADMIN", "127.0.0.1:15002")
	originAddr := env("TAPLINE_ORIGIN", "127.0.0.1:15001")
	runOriginFlag := env("TAPLINE_RUN_ORIGIN", "1") != "0"
	id := Identity{
		Instance:  env("TAPLINE_INSTANCE", hostname()),
		Namespace: env("TAPLINE_NAMESPACE", "default"),
	}
	store := newStore(sinkFromEnv(env("TAPLINE_SINK", "stdout"), id))
	conf := &ProxyConfig{
		Mode: "builtin", CustomUpstream: app, TimeoutMs: 8000,
		ProxyProtocol: env("TAPLINE_PROXY_PROTOCOL", "0") != "0",
		Listen:        inbound, Envoy: app, Inbound: inbound, Outbound: outbound, App: app,
	}
	var cfgMu sync.RWMutex

	if runOriginFlag {
		go func() {
			if err := runOrigin(originAddr); err != nil {
				fmt.Fprintln(os.Stderr, "origin failed:", err)
			}
		}()
		time.Sleep(80 * time.Millisecond)
	}
	go func() {
		if err := serveAdmin(adminAddr, store, &cfgMu, conf); err != nil {
			fmt.Fprintln(os.Stderr, "admin failed:", err)
		}
	}()

	if err := spawnListener(inbound, hopInbound, store, &cfgMu, conf); err != nil {
		fmt.Fprintln(os.Stderr, "inbound listen:", err)
		os.Exit(1)
	}
	if outbound != "0" && outbound != "" {
		if err := spawnListener(outbound, hopOutbound, store, &cfgMu, conf); err != nil {
			fmt.Fprintln(os.Stderr, "outbound listen:", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "tapline inbound  %s  → app (Envoy already decrypted)\n", inbound)
	fmt.Fprintf(os.Stderr, "tapline outbound %s → orig-dst (Istio intercepts to :15001)\n", outbound)
	fmt.Fprintf(os.Stderr, "tapline admin    %s\n", adminAddr)
	select {}
}

func spawnListener(addr string, h hop, store *Store, cfg *sync.RWMutex, conf *ProxyConfig) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				fmt.Fprintln(os.Stderr, "accept", err)
				continue
			}
			go func(c net.Conn) {
				if err := handle(h, c, store, cfg, conf, NoopInspector{}); err != nil {
					fmt.Fprintln(os.Stderr, "conn", c.RemoteAddr(), err)
				}
			}(c)
		}
	}()
	return nil
}

func handle(h hop, client net.Conn, store *Store, cfg *sync.RWMutex, conf *ProxyConfig, insp Inspector) error {
	defer client.Close()
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	orig := originalDst(client)
	cfg.RLock()
	snapshot := *conf
	cfg.RUnlock()
	timeout := time.Duration(snapshot.TimeoutMs) * time.Millisecond
	started := time.Now()
	direction := "inbound"
	if h == hopOutbound {
		direction = "outbound"
	}
	peer, _ := client.RemoteAddr().(*net.TCPAddr)
	local, _ := client.LocalAddr().(*net.TCPAddr)

	var upstreamAddr string
	switch h {
	case hopInbound:
		if orig != nil && orig.Port != 15003 && orig.Port != 0 {
			upstreamAddr = fmt.Sprintf("127.0.0.1:%d", orig.Port)
		} else {
			upstreamAddr = snapshot.App
		}
	case hopOutbound:
		if orig == nil {
			e := skeleton(peer, local, orig, direction, "")
			msg := "missing_so_original_dst"
			e.Error = &msg
			e.Status = -1
			e.CloseReason = "error"
			store.Record(e)
			return nil
		}
		upstreamAddr = orig.String()
	}

	entry := skeleton(peer, local, orig, direction, upstreamAddr)
	d := net.Dialer{Timeout: timeout}
	up, err := d.Dial("tcp", upstreamAddr)
	if err != nil {
		msg := err.Error()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			msg = "upstream_timeout"
		}
		entry.Error = &msg
		entry.Status = -1
		entry.DurationMs = uint64(time.Since(started).Milliseconds())
		if msg == "upstream_timeout" {
			entry.CloseReason = "idle"
		} else {
			entry.CloseReason = "error"
		}
		store.Record(entry)
		return err
	}
	defer up.Close()
	if tc, ok := up.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return splice(client, up, store, entry, insp, started)
}

func skeleton(peer, local, orig *net.TCPAddr, direction, upstream string) Entry {
	origS := ""
	if orig != nil {
		origS = orig.String()
	}
	e := Entry{
		ID: newID(), TS: nowMS(), Method: "TCP", Path: "*", Status: 0,
		Upstream: upstream, Source: "proxy", Protocol: "tcp",
		OriginalDst: origS, Direction: direction,
		Instance: env("TAPLINE_INSTANCE", hostname()), Namespace: env("TAPLINE_NAMESPACE", "default"),
		RequestHeaders: []HeaderPair{}, ResponseHeaders: []HeaderPair{},
	}
	if peer != nil {
		e.ClientIP = peer.IP.String()
		e.ClientPort = peer.Port
	}
	if local != nil {
		e.LocalPort = local.Port
	}
	return e
}

func splice(client, upstream net.Conn, store *Store, entry Entry, insp Inspector, started time.Time) error {
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	peek := make([]byte, 16384)
	n, err := client.Read(peek)
	_ = client.SetReadDeadline(time.Time{})
	if n > 0 {
		insp.OnBytes(DirUpstream, peek[:n])
		p := classify(peek[:n])
		entry.Protocol, entry.Method, entry.Path, entry.Query, entry.ContentType = p.Protocol, p.Method, p.Path, p.Query, p.ContentType
		entry.TlsSni = p.SNI
		if p.Host != "" {
			entry.URL = p.Host + entry.Path
			if p.Protocol == "tls" {
				entry.URL = p.Host
			}
		}
		if _, werr := upstream.Write(peek[:n]); werr != nil {
			msg := werr.Error()
			entry.Error = &msg
			entry.Status = -1
			entry.RequestBytes = uint64(n)
			entry.DurationMs = uint64(time.Since(started).Milliseconds())
			entry.CloseReason = classifyClose(werr)
			fillTCPInfo(&entry, client)
			store.Record(entry)
			return werr
		}
		entry.RequestBytes = uint64(n)
	} else if err != nil && !isTimeout(err) {
		msg := err.Error()
		entry.Error = &msg
		entry.Status = -1
		entry.DurationMs = uint64(time.Since(started).Milliseconds())
		entry.CloseReason = classifyClose(err)
		fillTCPInfo(&entry, client)
		store.Record(entry)
		return err
	}

	var upN, downN uint64
	var status int
	var closeErr error
	var closeMu sync.Mutex
	note := func(err error) {
		if err == nil || err == io.EOF {
			return
		}
		closeMu.Lock()
		closeErr = worseErr(closeErr, err)
		closeMu.Unlock()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(upstream, client)
		upN = uint64(n)
		note(err)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		first := true
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if first {
					status = httpStatus(buf[:n])
					first = false
				}
				if _, werr := client.Write(buf[:n]); werr != nil {
					downN += uint64(n)
					note(werr)
					break
				}
				downN += uint64(n)
			}
			if err != nil {
				if err != io.EOF {
					note(err)
				}
				break
			}
		}
		closeWrite(client)
	}()
	wg.Wait()
	entry.RequestBytes += upN
	entry.ResponseBytes = downN
	if status > 0 {
		entry.Status = status
	}
	entry.DurationMs = uint64(time.Since(started).Milliseconds())
	entry.CloseReason = classifyClose(closeErr)
	fillTCPInfo(&entry, client)
	store.Record(entry)
	return nil
}

func fillTCPInfo(e *Entry, c net.Conn) {
	if rtt, retrans, ok := tcpKernelInfo(c); ok {
		e.TcpRttUs = rtt
		e.TcpRetrans = retrans
	}
}

func classifyClose(err error) string {
	if err == nil || errors.Is(err, io.EOF) {
		return "fin"
	}
	if isTimeout(err) {
		return "idle"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "rst"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		if errors.Is(op.Err, syscall.ECONNRESET) {
			return "rst"
		}
	}
	return "error"
}

func worseErr(cur, next error) error {
	if cur == nil {
		return next
	}
	if classifyClose(next) == "rst" {
		return next
	}
	return cur
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	if h := os.Getenv("HOSTNAME"); h != "" {
		return h
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "tapline"
	}
	return h
}
