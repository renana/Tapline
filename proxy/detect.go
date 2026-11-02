package main

import (
	"bytes"
	"strconv"
	"strings"
)

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("PATCH "),
	[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "), []byte("CONNECT "),
	[]byte("TRACE "),
}

type Probe struct {
	Protocol    string
	Method      string
	Path        string
	Query       string
	Host        string
	ContentType string
	Upgrade     string
	GRPC        bool
	SNI         string
}

func classify(buf []byte) Probe {
	if len(buf) == 0 {
		return Probe{Protocol: "tcp", Method: "TCP", Path: "*"}
	}
	if bytes.HasPrefix(buf, h2Preface) {
		return classifyH2(buf[len(h2Preface):])
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(buf, m) {
			return classifyHTTP1(buf)
		}
	}
	if isTLSClientHello(buf) {
		return classifyTLS(buf)
	}
	return Probe{Protocol: "tcp", Method: "TCP", Path: "*"}
}

func classifyHTTP1(buf []byte) Probe {
	p := Probe{Protocol: "http1", Method: "HTTP", Path: "*"}
	line, rest, _ := bytes.Cut(buf, []byte("\r\n"))
	fields := bytes.Fields(line)
	if len(fields) >= 1 {
		p.Method = string(fields[0])
	}
	if len(fields) >= 2 {
		target := string(fields[1])
		if i := strings.IndexByte(target, '?'); i >= 0 {
			p.Path = target[:i]
			p.Query = target[i+1:]
		} else {
			p.Path = target
		}
	}
	for {
		var hdr []byte
		hdr, rest, _ = bytes.Cut(rest, []byte("\r\n"))
		if len(hdr) == 0 {
			break
		}
		name, val, ok := bytes.Cut(hdr, []byte(":"))
		if !ok {
			continue
		}
		key := strings.ToLower(string(bytes.TrimSpace(name)))
		v := strings.TrimSpace(string(val))
		switch key {
		case "host":
			p.Host = v
		case "content-type":
			p.ContentType = v
		case "upgrade":
			p.Upgrade = v
		}
	}
	if strings.Contains(strings.ToLower(p.Upgrade), "websocket") {
		p.Protocol = "websocket"
	}
	return p
}

func isTLSClientHello(buf []byte) bool {
	return len(buf) >= 6 && buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x01
}

func classifyTLS(buf []byte) Probe {
	p := Probe{Protocol: "tls", Method: "TLS", Path: "*"}
	if sni := parseSNI(buf); sni != "" {
		p.SNI = sni
		p.Host = sni
		p.Path = sni
	}
	return p
}

func parseSNI(buf []byte) string {
	// TLS record: type(1) ver(2) len(2) + handshake
	if len(buf) < 5 || buf[0] != 0x16 {
		return ""
	}
	rec := int(buf[3])<<8 | int(buf[4])
	off := 5
	if off+rec > len(buf) {
		rec = len(buf) - off
	}
	h := buf[off : off+rec]
	if len(h) < 4 || h[0] != 0x01 {
		return ""
	}
	hsLen := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	p := h[4:]
	if hsLen < len(p) {
		p = p[:hsLen]
	}
	if len(p) < 34 {
		return ""
	}
	p = p[34:] // client version (2) + random (32)
	if len(p) < 1 {
		return ""
	}
	sid := int(p[0])
	p = p[1:]
	if len(p) < sid+2 {
		return ""
	}
	p = p[sid:]
	cs := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < cs+1 {
		return ""
	}
	p = p[cs:]
	cm := int(p[0])
	p = p[1:]
	if len(p) < cm+2 {
		return ""
	}
	p = p[cm:]
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen > len(p) {
		extLen = len(p)
	}
	p = p[:extLen]
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		n := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if n > len(p) {
			return ""
		}
		data := p[:n]
		p = p[n:]
		if typ != 0 {
			continue
		}
		// SNI: list_len(2) name_type(1) name_len(2) name
		if len(data) < 5 {
			return ""
		}
		if data[2] != 0 {
			continue
		}
		nl := int(data[3])<<8 | int(data[4])
		if 5+nl > len(data) {
			return ""
		}
		return string(data[5 : 5+nl])
	}
	return ""
}

func classifyH2(after []byte) Probe {
	p := Probe{Protocol: "h2", Method: "H2", Path: "*"}
	off := 0
	for off+9 <= len(after) {
		n := int(after[off])<<16 | int(after[off+1])<<8 | int(after[off+2])
		ty := after[off+3]
		flags := after[off+4]
		end := off + 9 + n
		if end > len(after) {
			break
		}
		if ty == 0x1 {
			frag := after[off+9 : end]
			if flags&0x8 != 0 {
				if len(frag) == 0 {
					break
				}
				pad := int(frag[0])
				frag = frag[1:]
				if pad > len(frag) {
					break
				}
				frag = frag[:len(frag)-pad]
			}
			if flags&0x20 != 0 {
				if len(frag) < 5 {
					break
				}
				frag = frag[5:]
			}
			applyHPack(&p, frag)
			break
		}
		off = end
	}
	if p.GRPC || strings.Contains(strings.ToLower(p.ContentType), "grpc") {
		p.Protocol = "grpc"
		p.GRPC = true
	}
	return p
}

// Minimal HPACK: static-table indexed + literal (Huffman or raw) for the first
// HEADERS block. Enough for :method/:path/:authority/content-type.
func applyHPack(p *Probe, b []byte) {
	i := 0
	for i < len(b) {
		x := b[i]
		switch {
		case x&0x80 != 0:
			idx, n := readInt(b[i:], 7)
			i += n
			name, val := staticHeader(idx)
			setH2(p, name, val)
		case x&0xc0 == 0x40:
			idx, n := readInt(b[i:], 6)
			i += n
			name := ""
			if idx == 0 {
				var v string
				name, v, i = readHPackString(b, i)
				_ = v
			} else {
				name, _ = staticHeader(idx)
			}
			val, ni := readHPackStringVal(b, i)
			i = ni
			setH2(p, name, val)
		default:
			nbits := 4
			if x&0xe0 == 0x20 {
				_, n := readInt(b[i:], 5)
				i += n
				continue
			}
			if x&0xf0 == 0 {
				nbits = 4
			}
			idx, n := readInt(b[i:], nbits)
			i += n
			name := ""
			if idx == 0 {
				name, _, i = readHPackString(b, i)
			} else {
				name, _ = staticHeader(idx)
			}
			val, ni := readHPackStringVal(b, i)
			i = ni
			setH2(p, name, val)
		}
	}
}

func setH2(p *Probe, name, val string) {
	switch name {
	case ":method":
		p.Method = val
	case ":path":
		if i := strings.IndexByte(val, '?'); i >= 0 {
			p.Path = val[:i]
			p.Query = val[i+1:]
		} else {
			p.Path = val
		}
	case ":authority":
		p.Host = val
	case "content-type":
		p.ContentType = val
		p.GRPC = strings.Contains(strings.ToLower(val), "grpc")
	}
}

func readInt(b []byte, prefix int) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	mask := (1 << prefix) - 1
	v := int(b[0]) & mask
	if v < mask {
		return v, 1
	}
	m, i, n := 0, 1, v
	for i < len(b) {
		n += int(b[i]&0x7f) << m
		i++
		if b[i-1]&0x80 == 0 {
			break
		}
		m += 7
	}
	return n, i
}

func readHPackString(b []byte, i int) (string, string, int) {
	s, n := readHPackStringVal(b, i)
	return s, "", n
}

func readHPackStringVal(b []byte, i int) (string, int) {
	if i >= len(b) {
		return "", i
	}
	huff := b[i]&0x80 != 0
	n, k := readInt(b[i:], 7)
	i += k
	if i+n > len(b) {
		n = len(b) - i
	}
	raw := b[i : i+n]
	i += n
	if huff {
		return huffDecode(raw), i
	}
	return string(raw), i
}

func staticHeader(idx int) (string, string) {
	if idx <= 0 || idx >= len(hpackStatic) {
		return "", ""
	}
	return hpackStatic[idx][0], hpackStatic[idx][1]
}

func httpStatus(buf []byte) int {
	if !bytes.HasPrefix(buf, []byte("HTTP/1.")) {
		return 0
	}
	sp := bytes.IndexByte(buf, ' ')
	if sp < 0 || sp+4 > len(buf) {
		return 0
	}
	code, err := strconv.Atoi(string(buf[sp+1 : sp+4]))
	if err != nil {
		return 0
	}
	return code
}

// HPACK static table (RFC 7541 Appendix A), 1-based.
var hpackStatic = [][2]string{
	{},
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

func huffDecode(src []byte) string {
	// Incomplete table: don't emit garbage. Protocol still classifies as h2/grpc.
	_ = src
	return ""
}
