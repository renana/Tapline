package main

import (
	"sync"
	"sync/atomic"
	"time"
)

const maxLogs = 400
const seriesLen = 60

type HeaderPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Entry struct {
	ID              string       `json:"id"`
	TS              uint64       `json:"ts"`
	Method          string       `json:"method"`
	Path            string       `json:"path"`
	Query           string       `json:"query"`
	Status          int          `json:"status"`
	DurationMs      uint64       `json:"durationMs"`
	ClientIP        string       `json:"clientIp"`
	RequestBytes    uint64       `json:"requestBytes"`
	ResponseBytes   uint64       `json:"responseBytes"`
	ContentType     string       `json:"contentType"`
	Upstream        string       `json:"upstream"`
	Error           *string      `json:"error"`
	Source          string       `json:"source"`
	Protocol        string       `json:"protocol"`
	OriginalDst     string       `json:"originalDst"`
	Direction       string       `json:"direction"`
	Instance        string       `json:"instance"`
	Namespace       string       `json:"namespace"`
	ClientPort      int          `json:"clientPort"`
	LocalPort       int          `json:"localPort"`
	CloseReason     string       `json:"closeReason"`
	TlsSni          string       `json:"tlsSni"`
	TcpRttUs        uint32       `json:"tcpRttUs"`
	TcpRetrans      uint32       `json:"tcpRetrans"`
	URL             string       `json:"url"`
	UserAgent       string       `json:"userAgent"`
	RequestHeaders  []HeaderPair `json:"requestHeaders"`
	ResponseHeaders []HeaderPair `json:"responseHeaders"`
	RequestBody     *string      `json:"requestBody"`
	ResponseBody    *string      `json:"responseBody"`
	Truncated       bool         `json:"truncated"`
}

type Summary struct {
	ID            string  `json:"id"`
	TS            uint64  `json:"ts"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Query         string  `json:"query"`
	Status        int     `json:"status"`
	DurationMs    uint64  `json:"durationMs"`
	ClientIP      string  `json:"clientIp"`
	RequestBytes  uint64  `json:"requestBytes"`
	ResponseBytes uint64  `json:"responseBytes"`
	ContentType   string  `json:"contentType"`
	Upstream      string  `json:"upstream"`
	Error         *string `json:"error"`
	Source        string  `json:"source"`
	Protocol      string  `json:"protocol"`
	OriginalDst   string  `json:"originalDst"`
	Direction     string  `json:"direction"`
	Instance      string  `json:"instance"`
	Namespace     string  `json:"namespace"`
	ClientPort    int     `json:"clientPort"`
	LocalPort     int     `json:"localPort"`
	CloseReason   string  `json:"closeReason"`
	TlsSni        string  `json:"tlsSni"`
	TcpRttUs      uint32  `json:"tcpRttUs"`
	TcpRetrans    uint32  `json:"tcpRetrans"`
}

func (e Entry) summary() Summary {
	return Summary{
		ID: e.ID, TS: e.TS, Method: e.Method, Path: e.Path, Query: e.Query,
		Status: e.Status, DurationMs: e.DurationMs, ClientIP: e.ClientIP,
		RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes,
		ContentType: e.ContentType, Upstream: e.Upstream, Error: e.Error,
		Source: e.Source, Protocol: e.Protocol, OriginalDst: e.OriginalDst,
		Direction: e.Direction, Instance: e.Instance, Namespace: e.Namespace,
		ClientPort: e.ClientPort, LocalPort: e.LocalPort, CloseReason: e.CloseReason,
		TlsSni: e.TlsSni, TcpRttUs: e.TcpRttUs, TcpRetrans: e.TcpRetrans,
	}
}

type Stats struct {
	Total       uint64  `json:"total"`
	OK          uint64  `json:"ok"`
	Redirect    uint64  `json:"redirect"`
	ClientError uint64  `json:"clientError"`
	ServerError uint64  `json:"serverError"`
	Failed      uint64  `json:"failed"`
	BytesIn     uint64  `json:"bytesIn"`
	BytesOut    uint64  `json:"bytesOut"`
	P50         uint64  `json:"p50"`
	P95         uint64  `json:"p95"`
	RPS         float64 `json:"rps"`
	Series      []uint64 `json:"series"`
}

type ProxyConfig struct {
	Mode           string `json:"mode"`
	CustomUpstream string `json:"customUpstream"`
	TimeoutMs      uint64 `json:"timeoutMs"`
	ProxyProtocol  bool   `json:"proxyProtocol"`
	Listen         string `json:"listen"`
	Envoy          string `json:"envoy"`
	Inbound        string `json:"inbound"`
	Outbound       string `json:"outbound"`
	App            string `json:"app"`
}

type Store struct {
	sink        Sink
	mu          sync.Mutex
	logs        []Entry
	total       atomic.Uint64
	ok          atomic.Uint64
	redirect    atomic.Uint64
	clientError atomic.Uint64
	serverError atomic.Uint64
	failed      atomic.Uint64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
}

func newStore(sink Sink) *Store {
	return &Store{sink: sink, logs: make([]Entry, 0, 64)}
}

func (s *Store) Record(e Entry) {
	if s.sink != nil {
		s.sink.Emit(&e)
	}
	s.total.Add(1)
	s.bytesIn.Add(e.RequestBytes)
	s.bytesOut.Add(e.ResponseBytes)
	switch {
	case e.Error != nil && e.Status <= 0:
		s.failed.Add(1)
	case e.Status >= 500:
		s.serverError.Add(1)
	case e.Status >= 400:
		s.clientError.Add(1)
	case e.Status >= 300:
		s.redirect.Add(1)
	default:
		s.ok.Add(1)
	}
	s.mu.Lock()
	s.logs = append([]Entry{e}, s.logs...)
	if len(s.logs) > maxLogs {
		s.logs = s.logs[:maxLogs]
	}
	s.mu.Unlock()
}

func (s *Store) Summaries() []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Summary, len(s.logs))
	for i := range s.logs {
		out[i] = s.logs[i].summary()
	}
	return out
}

func (s *Store) ByID(id string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.logs {
		if s.logs[i].ID == id {
			e := s.logs[i]
			return &e
		}
	}
	return nil
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.logs = s.logs[:0]
	s.mu.Unlock()
	s.total.Store(0)
	s.ok.Store(0)
	s.redirect.Store(0)
	s.clientError.Store(0)
	s.serverError.Store(0)
	s.failed.Store(0)
	s.bytesIn.Store(0)
	s.bytesOut.Store(0)
}

func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowMS()
	window := uint64(seriesLen * 1000)
	series := make([]uint64, seriesLen)
	dur := make([]uint64, 0, 120)
	for _, e := range s.logs {
		if len(dur) < 120 {
			dur = append(dur, e.DurationMs)
		}
		if now >= e.TS && now-e.TS < window {
			age := now - e.TS
			idx := int((window - 1 - age) / 1000)
			if idx > seriesLen-1 {
				idx = seriesLen - 1
			}
			if idx < 0 {
				idx = 0
			}
			series[idx]++
		}
	}
	sorted := append([]uint64(nil), dur...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var last5 uint64
	for i := seriesLen - 1; i >= seriesLen-5 && i >= 0; i-- {
		last5 += series[i]
	}
	return Stats{
		Total: s.total.Load(), OK: s.ok.Load(), Redirect: s.redirect.Load(),
		ClientError: s.clientError.Load(), ServerError: s.serverError.Load(),
		Failed: s.failed.Load(), BytesIn: s.bytesIn.Load(), BytesOut: s.bytesOut.Load(),
		P50: percentile(sorted, 50), P95: percentile(sorted, 95),
		RPS: float64(last5) / 5, Series: series,
	}
}

func percentile(sorted []uint64, p int) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * len(sorted) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func nowMS() uint64 {
	return uint64(time.Now().UnixMilli())
}

var idSeq atomic.Uint64

func newID() string {
	n := nowMS()<<12 | (idSeq.Add(1) & 0xfff)
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[n&0xf]
		n >>= 4
	}
	return string(b[:])
}
