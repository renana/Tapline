package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Identity struct {
	Instance  string
	Namespace string
}

type Sink interface {
	Emit(*Entry)
}

type nullSink struct{}

func (nullSink) Emit(*Entry) {}

type stdoutSink struct{ id Identity }

func (s stdoutSink) Emit(e *Entry) {
	fmt.Fprintln(os.Stdout, line(e, s.id))
}

type fileSink struct {
	id Identity
	mu sync.Mutex
	w  io.Writer
}

func (s *fileSink) Emit(e *Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintln(s.w, line(e, s.id))
}

type fanout []Sink

func (f fanout) Emit(e *Entry) {
	for _, s := range f {
		s.Emit(e)
	}
}

func sinkFromEnv(spec string, id Identity) Sink {
	parts := strings.Split(spec, ",")
	var sinks []Sink
	onlyNone := true
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch {
		case p == "none":
			continue
		case p == "" || p == "stdout":
			onlyNone = false
			sinks = append(sinks, stdoutSink{id})
		case strings.HasPrefix(p, "file:"):
			onlyNone = false
			f, err := os.OpenFile(strings.TrimPrefix(p, "file:"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tapline sink %s: %v\n", p, err)
				continue
			}
			sinks = append(sinks, &fileSink{id: id, w: f})
		default:
			onlyNone = false
			fmt.Fprintf(os.Stderr, "tapline unknown sink `%s` (try stdout, file:/path, none)\n", p)
		}
	}
	if onlyNone && strings.TrimSpace(spec) == "none" {
		return nullSink{}
	}
	if len(sinks) == 0 {
		return stdoutSink{id}
	}
	if len(sinks) == 1 {
		return sinks[0]
	}
	return fanout(sinks)
}

func line(e *Entry, id Identity) string {
	errStr := any(nil)
	if e.Error != nil {
		errStr = *e.Error
	}
	v := map[string]any{
		"_time": e.TS, "_msg": fmt.Sprintf("%s %s %s %d", e.Direction, e.Method, e.Path, e.Status),
		"app": "tapline", "id": e.ID, "direction": e.Direction, "protocol": e.Protocol,
		"method": e.Method, "path": e.Path, "query": e.Query, "status": e.Status,
		"duration_ms": e.DurationMs, "client_ip": e.ClientIP, "original_dst": e.OriginalDst,
		"upstream": e.Upstream, "bytes_in": e.RequestBytes, "bytes_out": e.ResponseBytes,
		"content_type": e.ContentType, "error": errStr, "instance": id.Instance, "namespace": id.Namespace,
		"client_port": e.ClientPort, "local_port": e.LocalPort, "close_reason": e.CloseReason,
		"tls_sni": e.TlsSni, "tcp_rtt_us": e.TcpRttUs, "tcp_retrans": e.TcpRetrans,
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
