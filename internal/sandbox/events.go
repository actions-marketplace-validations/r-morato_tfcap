package sandbox

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one thing the sandboxed command tried to do.
type Event struct {
	Kind   string `json:"kind"` // dns, connect, http, tls, exec, open
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Detail string `json:"detail,omitempty"`
	Leak   bool   `json:"leak,omitempty"` // contains the honeytoken canary
	Proc   string `json:"proc,omitempty"` // program responsible, when known
}

// Recorder collects events from concurrent listeners.
type Recorder struct {
	mu     sync.Mutex
	events []Event
	seen   map[string]bool
	honey  *Honey
}

func NewRecorder(h *Honey) *Recorder { return &Recorder{seen: map[string]bool{}, honey: h} }

func (r *Recorder) Add(e Event) {
	if r.honey != nil && !e.Leak {
		e.Leak = r.honey.Leaks(e.Host + " " + e.Detail)
	}
	if len(e.Detail) > 400 {
		e.Detail = e.Detail[:400] + "…"
	}
	k := fmt.Sprintf("%s|%s|%d|%s|%v|%s", e.Kind, e.Host, e.Port, e.Detail, e.Leak, e.Proc)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[k] {
		return
	}
	r.seen[k] = true
	r.events = append(r.events, e)
}

func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]Event(nil), r.events...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// ---- DNS ----

// ServeDNS answers every A query with 127.0.0.1 (so the follow-up
// connection reaches our listeners) and records the name.
func ServeDNS(pc net.PacketConn, r *Recorder) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		name, qtype, qend, ok := parseQuestion(buf[:n])
		if !ok {
			continue
		}
		r.Add(Event{Kind: "dns", Host: strings.TrimSuffix(name, ".")})
		resp := make([]byte, 0, qend+16)
		resp = append(resp, buf[:qend]...)
		resp[2] = 0x81 | buf[2]&0x01 // QR, RD copied
		resp[3] = 0x80               // RA, NOERROR
		binary.BigEndian.PutUint16(resp[6:], 0)
		binary.BigEndian.PutUint16(resp[8:], 0)
		binary.BigEndian.PutUint16(resp[10:], 0)
		if qtype == 1 {
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}

func dnsType(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 16:
		return "TXT"
	}
	return fmt.Sprintf("type%d", t)
}

func parseQuestion(b []byte) (name string, qtype uint16, end int, ok bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return "", 0, 0, false
	}
	i := 12
	var labels []string
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 || i+1+l > len(b) {
			return "", 0, 0, false
		}
		labels = append(labels, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(b) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(b[i:]), i + 4, true
}

// ---- TCP listeners ----

// ServeTCP accepts connections on l and records what the client sends:
// an HTTP request, a TLS ClientHello (for its SNI), a proxy CONNECT, or
// raw bytes.
func ServeTCP(l net.Listener, port int, r *Recorder) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handleConn(c, port, r)
	}
}

func handleConn(c net.Conn, port int, r *Recorder) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(c, 64<<10)
	first, err := br.Peek(1)
	if err != nil {
		r.Add(Event{Kind: "connect", Host: "(resolved via sandbox DNS)", Port: port})
		return
	}
	if first[0] == 0x16 { // TLS handshake
		sni := readSNI(br)
		r.Add(Event{Kind: "tls", Host: sni, Port: port})
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		raw, _ := io.ReadAll(io.LimitReader(br, 4096))
		r.Add(Event{Kind: "connect", Host: "(raw)", Port: port, Detail: string(append(first, raw...))})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if req.Method == http.MethodConnect {
		host, p := splitHostPort(req.Host, 443)
		r.Add(Event{Kind: "connect", Host: host, Port: p, Detail: "via proxy CONNECT"})
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if b, err := br.Peek(1); err == nil && b[0] == 0x16 {
			if sni := readSNI(br); sni != "" && sni != host {
				r.Add(Event{Kind: "tls", Host: sni, Port: p})
			}
		}
		return
	}
	host, def := req.Host, port
	if req.URL.Host != "" { // proxy form: GET http://host/path
		host, def = req.URL.Host, 80
	}
	h, p := splitHostPort(host, def)
	var hdr bytes.Buffer
	_ = req.Header.Write(&hdr)
	r.Add(Event{Kind: "http", Host: h, Port: p, Detail: req.Method + " " + req.URL.RequestURI() + "\n" + hdr.String() + string(body)})
	_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"))
}

func splitHostPort(hp string, def int) (string, int) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def
	}
	n := def
	fmt.Sscan(p, &n)
	return h, n
}

// readSNI reads a TLS ClientHello and returns its server_name.
func readSNI(br *bufio.Reader) string {
	hdr, err := br.Peek(5)
	if err != nil {
		return ""
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec, err := br.Peek(5 + n)
	if err != nil {
		return ""
	}
	sni, _ := parseClientHello(rec[5:])
	return sni
}

var errShort = errors.New("short")

func parseClientHello(b []byte) (string, error) {
	if len(b) < 42 || b[0] != 1 {
		return "", errShort
	}
	i := 4 + 2 + 32 // type+len, version, random
	if i >= len(b) {
		return "", errShort
	}
	i += 1 + int(b[i]) // session id
	if i+2 > len(b) {
		return "", errShort
	}
	i += 2 + int(binary.BigEndian.Uint16(b[i:])) // cipher suites
	if i >= len(b) {
		return "", errShort
	}
	i += 1 + int(b[i]) // compression
	if i+2 > len(b) {
		return "", errShort
	}
	end := i + 2 + int(binary.BigEndian.Uint16(b[i:]))
	i += 2
	for i+4 <= end && i+4 <= len(b) {
		typ := binary.BigEndian.Uint16(b[i:])
		l := int(binary.BigEndian.Uint16(b[i+2:]))
		i += 4
		if typ == 0 && i+5 <= len(b) {
			nl := int(binary.BigEndian.Uint16(b[i+3:]))
			if i+5+nl <= len(b) {
				return string(b[i+5 : i+5+nl]), nil
			}
		}
		i += l
	}
	return "", errShort
}
