package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// ==================== Environment ====================
var (
	UUID         = getEnv("UUID", "d1cf4b9c-3e57-085d-b34a-797fcf601381")
	SubPath      = getEnv("SUB_PATH", "vercel")
	Name         = getEnv("NAME", "Vercel-Node")
	AllowAnyUUID = getEnv("ALLOW_ANY_UUID", "true") == "true"
	ServerAddr   = strings.TrimSpace(os.Getenv("SERVER_ADDR"))
	WSHost       = strings.TrimSpace(os.Getenv("WS_HOST"))
	WSSNI        = strings.TrimSpace(os.Getenv("WS_SNI"))
	ShowLog      = os.Getenv("SHOW_LOG") == "true"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logf(format string, args ...interface{}) {
	if ShowLog {
		log.Printf(format, args...)
	}
}

// ==================== WebSocket Upgrader ====================
var upgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// ==================== Utilities ====================
func isBlockedDomain(host string) bool {
	blocked := []string{
		"speedtest.net", "fast.com", "speedtest.cn", "speed.cloudflare.com",
		"speedof.me", "testmy.net", "bandwidth.place", "speed.io",
		"librespeed.org", "speedcheck.org",
	}
	h := strings.ToLower(host)
	for _, b := range blocked {
		if h == b || strings.HasSuffix(h, "."+b) {
			return true
		}
	}
	return false
}

func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return host
	}
	return ips[0].String()
}

// ==================== VLESS ====================
func handleVLESS(ws *websocket.Conn, msg []byte) bool {
	if len(msg) < 18 {
		return false
	}
	version := msg[0]
	clientUUID := msg[1:17]
	if !AllowAnyUUID {
		expected, _ := hex.DecodeString(strings.ReplaceAll(UUID, "-", ""))
		if !hmac.Equal(clientUUID, expected) {
			return false
		}
	}

	i := 18 + int(msg[17]) + 1
	if len(msg) < i+3 {
		return false
	}
	port := binary.BigEndian.Uint16(msg[i : i+2])
	i += 2
	atyp := msg[i]
	i++

	var host string
	switch atyp {
	case 0x01:
		if len(msg) < i+4 {
			return false
		}
		host = net.IP(msg[i : i+4]).String()
		i += 4
	case 0x02:
		if len(msg) < i+1 {
			return false
		}
		l := int(msg[i])
		i++
		if len(msg) < i+l {
			return false
		}
		host = string(msg[i : i+l])
		i += l
	case 0x03:
		if len(msg) < i+16 {
			return false
		}
		host = net.IP(msg[i : i+16]).String()
		i += 16
	default:
		return false
	}

	if isBlockedDomain(host) {
		return false
	}

	if err := ws.WriteMessage(websocket.BinaryMessage, []byte{version, 0}); err != nil {
		return false
	}

	target := resolveHost(host)
	conn, err := net.Dial("tcp", net.JoinHostPort(target, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	defer conn.Close()

	if i < len(msg) {
		if _, err := conn.Write(msg[i:]); err != nil {
			return false
		}
	}

	bridge(ws, conn)
	return true
}

// ==================== Trojan ====================
func handleTrojan(ws *websocket.Conn, msg []byte) bool {
	if len(msg) < 58 {
		return false
	}
	received := string(msg[:56])
	if !AllowAnyUUID {
		h := sha256.Sum224([]byte(UUID))
		if received != hex.EncodeToString(h[:]) {
			return false
		}
	}

	off := 56
	if off+1 < len(msg) && msg[off] == 0x0d && msg[off+1] == 0x0a {
		off += 2
	}
	if off >= len(msg) || msg[off] != 0x01 {
		return false
	}
	off++
	if off >= len(msg) {
		return false
	}

	atyp := msg[off]
	off++
	var host string
	switch atyp {
	case 0x01:
		if len(msg) < off+4 {
			return false
		}
		host = net.IP(msg[off : off+4]).String()
		off += 4
	case 0x03:
		if len(msg) < off+1 {
			return false
		}
		l := int(msg[off])
		off++
		if len(msg) < off+l {
			return false
		}
		host = string(msg[off : off+l])
		off += l
	case 0x04:
		if len(msg) < off+16 {
			return false
		}
		host = net.IP(msg[off : off+16]).String()
		off += 16
	default:
		return false
	}

	if len(msg) < off+2 {
		return false
	}
	port := binary.BigEndian.Uint16(msg[off : off+2])
	off += 2
	if off+1 < len(msg) && msg[off] == 0x0d && msg[off+1] == 0x0a {
		off += 2
	}

	if isBlockedDomain(host) {
		return false
	}

	target := resolveHost(host)
	conn, err := net.Dial("tcp", net.JoinHostPort(target, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	defer conn.Close()

	if off < len(msg) {
		if _, err := conn.Write(msg[off:]); err != nil {
			return false
		}
	}

	bridge(ws, conn)
	return true
}

// ==================== VMess AEAD: KDF ====================
// Nested-HMAC construction (sesuai v2fly / Python asli)
func hmacWithHash(hashFn func([]byte) []byte, key, data []byte) []byte {
	k := key
	if len(k) > 64 {
		k = hashFn(k)
	}
	kb := make([]byte, 64)
	copy(kb, k)
	ipad := make([]byte, 64)
	opad := make([]byte, 64)
	for i := 0; i < 64; i++ {
		ipad[i] = kb[i] ^ 0x36
		opad[i] = kb[i] ^ 0x5c
	}
	inner := make([]byte, 64+len(data))
	copy(inner, ipad)
	copy(inner[64:], data)
	innerHash := hashFn(inner)
	outer := make([]byte, 64+len(innerHash))
	copy(outer, opad)
	copy(outer[64:], innerHash)
	return hashFn(outer)
}

func vmessKDF(key []byte, paths ...string) []byte {
	fn := func(data []byte) []byte {
		mac := hmac.New(sha256.New, []byte("VMess AEAD KDF"))
		mac.Write(data)
		return mac.Sum(nil)
	}
	for _, p := range paths {
		prevFn := fn
		pathBytes := []byte(p)
		fn = func(data []byte) []byte {
			return hmacWithHash(prevFn, pathBytes, data)
		}
	}
	return fn(key)
}

func vmessKDF16(key []byte, paths ...string) []byte {
	return vmessKDF(key, paths...)[:16]
}

func vmessCmdKey(uuid []byte) []byte {
	h := md5.New()
	h.Write(uuid)
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return h.Sum(nil)
}

// ==================== VMess Header ====================
type vmessHeader struct {
	Command         byte
	Address         string
	Port            uint16
	AddressType     byte
	Option          byte
	Security        byte
	WireSecurity    byte
	RequestBodyIV   []byte
	RequestBodyKey  []byte
	ResponseHeader  byte
	HeaderLength    int
	AuthID          []byte
	ResponseBodyKey []byte
	ResponseBodyIV  []byte
}

func tryParseVMessHeader(data []byte, uuid []byte) (*vmessHeader, error) {
	if len(data) < 42 {
		return nil, fmt.Errorf("too short")
	}
	cmdKey := vmessCmdKey(uuid)
	authID := data[:16]

	authKey := vmessKDF16(cmdKey, "AES Auth ID Encryption")
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	authPlain := make([]byte, 16)
	block.Decrypt(authPlain, authID)

	ts := int64(binary.BigEndian.Uint64(authPlain[:8]))
	if abs(ts-time.Now().Unix()) > 120 {
		return nil, fmt.Errorf("timestamp out of range")
	}

	encLen := data[16:34]
	connNonce := data[34:42]

	lenKey := vmessKDF16(cmdKey, "VMess Header AEAD Key_Length", string(authID), string(connNonce))
	lenIV := vmessKDF(cmdKey, "VMess Header AEAD Nonce_Length", string(authID), string(connNonce))[:12]

	lenBlock, _ := aes.NewCipher(lenKey)
	lenGCM, _ := cipher.NewGCM(lenBlock)
	lenPlain, err := lenGCM.Open(nil, lenIV, encLen, authID)
	if err != nil {
		return nil, err
	}
	plainLen := int(binary.BigEndian.Uint16(lenPlain))
	total := 42 + plainLen + 16
	if len(data) < total {
		return nil, fmt.Errorf("truncated")
	}

	hdrKey := vmessKDF16(cmdKey, "VMess Header AEAD Key", string(authID), string(connNonce))
	hdrIV := vmessKDF(cmdKey, "VMess Header AEAD Nonce", string(authID), string(connNonce))[:12]
	hdrBlock, _ := aes.NewCipher(hdrKey)
	hdrGCM, _ := cipher.NewGCM(hdrBlock)
	plain, err := hdrGCM.Open(nil, hdrIV, data[42:total], authID)
	if err != nil {
		return nil, err
	}

	rbi := plain[1:17]
	rbk := plain[17:33]
	respHeader := plain[33]
	option := plain[34]
	wireSec := plain[35] & 0x0f
	command := plain[37]
	security := wireSec
	if security == 6 {
		security = 5
		option &= ^byte(0x01 | 0x04 | 0x08 | 0x10)
	}

	p := 38
	var address string
	var port uint16
	atyp := byte(2)
	if command != 3 {
		port = binary.BigEndian.Uint16(plain[p : p+2])
		p += 2
		atyp = plain[p]
		p++
		switch atyp {
		case 1:
			address = net.IP(plain[p : p+4]).String()
			p += 4
		case 2:
			l := int(plain[p])
			p++
			address = string(plain[p : p+l])
			p += l
		case 3:
			address = net.IP(plain[p : p+16]).String()
			p += 16
		default:
			return nil, fmt.Errorf("invalid atyp")
		}
	}

	rbkArr := sha256.Sum256(rbk)
	rbiArr := sha256.Sum256(rbi)

	return &vmessHeader{
		Command:         command,
		Address:         address,
		Port:            port,
		AddressType:     atyp,
		Option:          option,
		Security:        security,
		WireSecurity:    wireSec,
		RequestBodyIV:   rbi,
		RequestBodyKey:  rbk,
		ResponseHeader:  respHeader,
		HeaderLength:    total,
		AuthID:          authID,
		ResponseBodyKey: rbkArr[:16],
		ResponseBodyIV:  rbiArr[:16],
	}, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ==================== VMess Body Decoder ====================
type vmessDecoder struct {
	header       *vmessHeader
	pending      []byte
	awaiting     bool
	nextSize     int
	nextPadding  int
	done         bool
	zeroRaw      bool
	sizeShake    *shakeParser
	paddingShake *shakeParser
	bodyNonce    *nonceCounter
	lengthNonce  *nonceCounter
	authLength   bool
	authLenKey   []byte
}

func newVMessDecoder(h *vmessHeader) *vmessDecoder {
	d := &vmessDecoder{
		header:      h,
		zeroRaw:     h.WireSecurity == 6 || (h.Security == 5 && h.Option&0x01 == 0),
		bodyNonce:   newNonceCounter(h.RequestBodyIV),
		lengthNonce: newNonceCounter(h.RequestBodyIV),
	}
	if h.Option&0x04 != 0 {
		d.sizeShake = newShakeParser(h.RequestBodyIV)
	}
	if h.Option&0x08 != 0 {
		d.paddingShake = d.sizeShake
	}
	if h.Option&0x10 != 0 && (h.Security == 3 || h.Security == 4) {
		d.authLength = true
		d.authLenKey = vmessKDF16(h.RequestBodyKey, "auth_len")
	}
	return d
}

func (d *vmessDecoder) push(chunk []byte) ([][]byte, error) {
	if d.done {
		return nil, nil
	}
	if d.zeroRaw {
		return [][]byte{chunk}, nil
	}
	d.pending = append(d.pending, chunk...)
	var out [][]byte
	for {
		if !d.awaiting {
			sbLen := 2
			if d.authLength {
				sbLen = 18
			}
			if len(d.pending) < sbLen {
				break
			}
			padding := 0
			if d.paddingShake != nil && d.header.Security != 5 {
				padding = d.paddingShake.nextPaddingLen()
			}
			raw := d.pending[:sbLen]
			var size int
			if d.authLength {
				nonce := d.lengthNonce.next()
				plain, err := openAEAD(d.header.Security, d.authLenKey, nonce, raw)
				if err != nil {
					return nil, err
				}
				size = int(binary.BigEndian.Uint16(plain)) + 16
			} else if d.sizeShake != nil {
				size = d.sizeShake.decodeSize(raw)
			} else {
				size = int(binary.BigEndian.Uint16(raw))
			}
			d.pending = d.pending[sbLen:]
			d.awaiting = true
			d.nextSize = size
			d.nextPadding = padding
		}
		if len(d.pending) < d.nextSize {
			break
		}
		frame := d.pending[:d.nextSize]
		d.pending = d.pending[d.nextSize:]
		d.awaiting = false
		if d.header.Security == 5 {
			if d.nextSize == 0 {
				d.done = true
				break
			}
			out = append(out, frame)
			continue
		}
		if d.nextSize == 16+d.nextPadding {
			d.done = true
			break
		}
		sealed := frame[:d.nextSize-d.nextPadding]
		nonce := d.bodyNonce.next()
		plain, err := openAEAD(d.header.Security, d.header.RequestBodyKey, nonce, sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, plain)
	}
	return out, nil
}

// ==================== VMess Body Encoder ====================
type vmessEncoder struct {
	header       *vmessHeader
	responseKey  []byte
	responseIV   []byte
	zeroRaw      bool
	sizeShake    *shakeParser
	paddingShake *shakeParser
	bodyNonce    *nonceCounter
	lengthNonce  *nonceCounter
	authLength   bool
	authLenKey   []byte
}

func newVMessEncoder(h *vmessHeader) *vmessEncoder {
	e := &vmessEncoder{
		header:      h,
		responseKey: h.ResponseBodyKey,
		responseIV:  h.ResponseBodyIV,
		zeroRaw:     h.WireSecurity == 6 || (h.Security == 5 && h.Option&0x01 == 0),
		bodyNonce:   newNonceCounter(h.ResponseBodyIV),
		lengthNonce: newNonceCounter(h.RequestBodyIV),
	}
	if h.Option&0x04 != 0 {
		e.sizeShake = newShakeParser(h.ResponseBodyIV)
	}
	if h.Option&0x08 != 0 {
		e.paddingShake = e.sizeShake
	}
	if h.Option&0x10 != 0 && (h.Security == 3 || h.Security == 4) {
		e.authLength = true
		e.authLenKey = vmessKDF16(h.RequestBodyKey, "auth_len")
	}
	return e
}

func (e *vmessEncoder) encode(data []byte) []byte {
	if e.zeroRaw {
		return data
	}
	var out []byte
	for i := 0; i < len(data); i += 8192 {
		end := i + 8192
		if end > len(data) {
			end = len(data)
		}
		out = append(out, e.unit(data[i:end])...)
	}
	return out
}

func (e *vmessEncoder) unit(p []byte) []byte {
	if e.header.Security == 5 {
		size := len(p)
		var sb []byte
		if e.sizeShake != nil {
			sb = e.sizeShake.encodeSize(size)
		} else {
			sb = make([]byte, 2)
			binary.BigEndian.PutUint16(sb, uint16(size))
		}
		return append(sb, p...)
	}
	padding := 0
	if e.paddingShake != nil {
		padding = e.paddingShake.nextPaddingLen()
	}
	nonce := e.bodyNonce.next()
	sealed := sealAEAD(e.header.Security, e.responseKey, nonce, p)
	size := len(sealed) + padding
	var sb []byte
	if e.authLength {
		ps := size - 16
		plain := make([]byte, 2)
		binary.BigEndian.PutUint16(plain, uint16(ps))
		nonce2 := e.lengthNonce.next()
		sb = sealAEAD(e.header.Security, e.authLenKey, nonce2, plain)
	} else if e.sizeShake != nil {
		sb = e.sizeShake.encodeSize(size)
	} else {
		sb = make([]byte, 2)
		binary.BigEndian.PutUint16(sb, uint16(size))
	}
	out := append(sb, sealed...)
	if padding > 0 {
		pad := make([]byte, padding)
		rand.Read(pad)
		out = append(out, pad...)
	}
	return out
}

// ==================== VMess Response Header ====================
func encodeVMessResponseHeader(h *vmessHeader) []byte {
	plain := []byte{h.ResponseHeader, 0, 0, 0}
	lenPlain := []byte{0, byte(len(plain))}

	lenKey := vmessKDF16(h.ResponseBodyKey, "AEAD Resp Header Len Key")
	lenIV := vmessKDF(h.ResponseBodyIV, "AEAD Resp Header Len IV")[:12]
	plKey := vmessKDF16(h.ResponseBodyKey, "AEAD Resp Header Key")
	plIV := vmessKDF(h.ResponseBodyIV, "AEAD Resp Header IV")[:12]

	var out []byte
	out = append(out, sealAEAD(3, lenKey, lenIV, lenPlain)...)
	out = append(out, sealAEAD(3, plKey, plIV, plain)...)
	return out
}

// ==================== AEAD Helper ====================
func openAEAD(security byte, key, nonce, sealed []byte) ([]byte, error) {
	if security == 3 {
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, nonce, sealed, nil)
	} else if security == 4 {
		aead, err := chacha20poly1305.New(chachaKey(key[:16]))
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, nonce, sealed, nil)
	}
	return nil, fmt.Errorf("unsupported security: %d", security)
}

func sealAEAD(security byte, key, nonce, plain []byte) []byte {
	if security == 3 {
		block, _ := aes.NewCipher(key[:16])
		gcm, _ := cipher.NewGCM(block)
		return gcm.Seal(nil, nonce, plain, nil)
	} else if security == 4 {
		aead, _ := chacha20poly1305.New(chachaKey(key[:16]))
		return aead.Seal(nil, nonce, plain, nil)
	}
	return nil
}

func chachaKey(k []byte) []byte {
	a := md5.Sum(k)
	b := md5.Sum(a[:])
	return append(a[:], b[:]...)
}

// ==================== SHAKE128 ====================
type shakeParser struct {
	shake io.Reader
}

func newShakeParser(seed []byte) *shakeParser {
	h := sha3.NewShake128()
	h.Write(seed) // WAJIB: absorb seed
	return &shakeParser{shake: h}
}

func (s *shakeParser) nextUint16() uint16 {
	var b [2]byte
	s.shake.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func (s *shakeParser) decodeSize(data []byte) int {
	return int(binary.BigEndian.Uint16(data)) ^ int(s.nextUint16())
}

func (s *shakeParser) encodeSize(size int) []byte {
	v := uint16(size) ^ s.nextUint16()
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func (s *shakeParser) nextPaddingLen() int {
	return int(s.nextUint16()) % 64
}

// ==================== Nonce Counter ====================
type nonceCounter struct {
	base  []byte
	count uint16
	mu    sync.Mutex
}

func newNonceCounter(iv []byte) *nonceCounter {
	n := make([]byte, len(iv))
	copy(n, iv)
	return &nonceCounter{base: n}
}

func (n *nonceCounter) next() []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]byte, len(n.base))
	copy(out, n.base)
	out[0] = byte(n.count >> 8)
	out[1] = byte(n.count)
	n.count++
	if len(out) < 12 {
		return out
	}
	return out[:12]
}

// ==================== Bridge ====================
func bridge(ws *websocket.Conn, conn net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := conn.Write(msg); err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	<-done
	conn.Close()
	ws.Close()
}

// ==================== VMess Handler ====================
func handleVMess(ws *websocket.Conn, msg []byte) bool {
	uuidBytes, _ := hex.DecodeString(strings.ReplaceAll(UUID, "-", ""))
	header, err := tryParseVMessHeader(msg, uuidBytes)
	if err != nil {
		logf("VMess parse error: %v", err)
		return false
	}
	if isBlockedDomain(header.Address) {
		return false
	}

	decoder := newVMessDecoder(header)
	encoder := newVMessEncoder(header)
	if err := ws.WriteMessage(websocket.BinaryMessage, encodeVMessResponseHeader(header)); err != nil {
		return false
	}

	target := resolveHost(header.Address)
	conn, err := net.Dial("tcp", net.JoinHostPort(target, fmt.Sprint(header.Port)))
	if err != nil {
		return false
	}
	defer conn.Close()

	if len(msg) > header.HeaderLength {
		remainder := msg[header.HeaderLength:]
		plain, err := decoder.push(remainder)
		if err != nil {
			return false
		}
		for _, p := range plain {
			conn.Write(p)
		}
	}

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			plain, err := decoder.push(data)
			if err != nil {
				return
			}
			for _, p := range plain {
				if _, err := conn.Write(p); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			encoded := encoder.encode(buf[:n])
			if len(encoded) > 0 {
				if err := ws.WriteMessage(websocket.BinaryMessage, encoded); err != nil {
					return
				}
			}
		}
	}()

	<-done
	conn.Close()
	ws.Close()
	return true
}

// ==================== WebSocket Router ====================
func wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logf("Upgrade error: %v", err)
		return
	}
	defer ws.Close()

	_, msg, err := ws.ReadMessage()
	if err != nil {
		return
	}

	var ok bool
	switch r.URL.Path {
	case "/vless":
		ok = handleVLESS(ws, msg)
	case "/trojan":
		ok = handleTrojan(ws, msg)
	case "/vmess":
		ok = handleVMess(ws, msg)
	default:
		ok = false
	}
	if !ok {
		ws.Close()
	}
}

// ==================== Subscription Builder ====================
func buildSubscription(r *http.Request) string {
	domain := r.Host
	if ServerAddr != "" {
		domain = ServerAddr
	}
	wsHost := domain
	if WSHost != "" {
		wsHost = WSHost
	}
	wsSNI := wsHost
	if WSSNI != "" {
		wsSNI = WSSNI
	}

	namePart := Name
	if namePart == "" {
		namePart = "Vercel-Node"
	}

	var lines []string

	lines = append(lines,
		fmt.Sprintf("vless://%s@%s:443?path=%%2Fvless&security=tls&encryption=none&host=%s&fp=chrome&type=ws&sni=%s#%s-VLESS-TLS",
			UUID, domain, wsHost, wsSNI, namePart),
		fmt.Sprintf("vless://%s@%s:80?path=%%2Fvless&security=none&encryption=none&host=%s&type=ws#%s-VLESS-NTLS",
			UUID, domain, wsHost, namePart),
	)
	lines = append(lines,
		fmt.Sprintf("trojan://%s@%s:443?path=%%2Ftrojan&security=tls&host=%s&fp=chrome&type=ws&sni=%s#%s-Trojan-TLS",
			UUID, domain, wsHost, wsSNI, namePart),
		fmt.Sprintf("trojan://%s@%s:80?path=%%2Ftrojan&security=none&host=%s&type=ws#%s-Trojan-NTLS",
			UUID, domain, wsHost, namePart),
	)

	vmessTLS := map[string]interface{}{
		"v": "2", "ps": namePart + "-VMess-TLS",
		"add": domain, "port": "443", "id": UUID, "aid": "0",
		"scy": "auto", "net": "ws", "type": "none",
		"host": wsHost, "path": "/vmess",
		"tls": "tls", "sni": wsSNI, "alpn": "", "fp": "chrome",
	}
	j, _ := json.Marshal(vmessTLS)
	lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString(j))

	vmessNTLS := map[string]interface{}{
		"v": "2", "ps": namePart + "-VMess-NTLS",
		"add": domain, "port": "80", "id": UUID, "aid": "0",
		"scy": "auto", "net": "ws", "type": "none",
		"host": wsHost, "path": "/vmess",
		"tls": "none", "sni": "", "alpn": "", "fp": "",
	}
	j2, _ := json.Marshal(vmessNTLS)
	lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString(j2))

	return strings.Join(lines, "\n")
}

// ==================== HTTP Handlers ====================
func subHandler(w http.ResponseWriter, r *http.Request) {
	sub := buildSubscription(r)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(sub)) + "\n"))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"ok":          true,
		"uuid":        UUID,
		"sub_path":    SubPath,
		"server_addr": ServerAddr,
		"ws_host":     WSHost,
		"ws_sni":      WSSNI,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f1115;color:#e6e6e6;padding:40px">
<h1>Node Proxy Aktif</h1>
<p>Subscription: <a style="color:#7dd3fc" href="/` + SubPath + `">/` + SubPath + `</a></p>
</body></html>`))
}

// ==================== Main ====================
func main() {
	http.HandleFunc("/vless", wsHandler)
	http.HandleFunc("/trojan", wsHandler)
	http.HandleFunc("/vmess", wsHandler)
	http.HandleFunc("/"+SubPath, subHandler)
	http.HandleFunc("/vercel", subHandler)
	http.HandleFunc("/sub", subHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", indexHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("Server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
