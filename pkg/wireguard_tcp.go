package pkg

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
)

// This file implements WireGuard-over-TCP encapsulation for the broker. It is
// kept deliberately separate from the default UDP path (which continues to use
// conn.NewDefaultBind()) so the common case stays easy to reason about.
//
// The wire format matches the gateway's TCP WireGuard listener: each WireGuard
// datagram is sent as a uint16 big-endian payload length followed by that many
// payload bytes. The broker dials the gateway's TCP listener, frames every
// outbound datagram, and decapsulates inbound frames back into the WireGuard
// receive path.

const (
	// tcpMaxFramePayload is the largest WireGuard datagram we can encapsulate in a
	// single length-prefixed frame. The 2-byte big-endian length prefix caps this
	// at 65535 bytes.
	tcpMaxFramePayload = 65535

	tcpDialTimeout         = 10 * time.Second
	tcpReconnectMinBackoff = 500 * time.Millisecond
	tcpReconnectMaxBackoff = 30 * time.Second

	// tcpRecvQueueSize bounds the number of decapsulated payloads buffered between
	// the TCP read loop and WireGuard's receive func.
	tcpRecvQueueSize = 128
)

var errFrameTooLarge = fmt.Errorf("wireguard tcp frame payload exceeds %d bytes", tcpMaxFramePayload)
var errTcpBindNotConnected = fmt.Errorf("wireguard tcp transport is not connected")

// writeFrame encapsulates a single WireGuard datagram as a 2-byte big-endian
// length prefix followed by the payload bytes. The frame is written with a
// single Write call so a partial failure cannot split a length prefix from its
// payload on the wire.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > tcpMaxFramePayload {
		return errFrameTooLarge
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	_, err := w.Write(frame)
	return err
}

// readFrame reads a single length-prefixed frame (written by writeFrame or the
// gateway) and returns the decapsulated payload. A zero-length frame returns a
// nil payload, which callers may ignore.
func readFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[:])
	if length == 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// tcpEndpoint identifies the gateway peer for the TCP transport. WireGuard
// treats the endpoint as opaque routing metadata; since the TCP bind manages a
// single connection to the gateway, only one endpoint is ever in play.
type tcpEndpoint struct {
	addr netip.AddrPort
}

var _ conn.Endpoint = (*tcpEndpoint)(nil)

func (e *tcpEndpoint) ClearSrc()           {}
func (e *tcpEndpoint) SrcToString() string { return "" }
func (e *tcpEndpoint) DstToString() string { return e.addr.String() }
func (e *tcpEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}
func (e *tcpEndpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (e *tcpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// wireguardTcpBind is a conn.Bind that tunnels WireGuard packets over a single
// outbound TCP connection to the gateway, reconnecting with bounded backoff on
// failure. It is used in place of conn.NewDefaultBind() when TCP transport is
// enabled.
type wireguardTcpBind struct {
	address  string
	endpoint atomic.Pointer[tcpEndpoint]
	logger   *log.Entry

	mu     sync.Mutex
	conn   net.Conn // current connection; nil while (re)connecting
	open   bool
	closed bool

	recvCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
}

var _ conn.Bind = (*wireguardTcpBind)(nil)

// NewWireguardTcpBind returns a conn.Bind that encapsulates WireGuard traffic
// over an outbound TCP connection to address (host:port of the gateway's TCP
// listener).
func NewWireguardTcpBind(address string, logger *log.Entry) *wireguardTcpBind {
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	b := &wireguardTcpBind{
		address: address,
		logger:  logger.WithField("wireguard_tcp_address", address),
	}
	// Seed the endpoint from the dial address so the receive path has something
	// to report even before WireGuard parses the configured endpoint.
	if addr, err := netip.ParseAddrPort(address); err == nil {
		b.endpoint.Store(&tcpEndpoint{addr: addr})
	}
	return b
}

func (b *wireguardTcpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true
	b.closed = false
	b.recvCh = make(chan []byte, tcpRecvQueueSize)
	b.closeCh = make(chan struct{})

	b.wg.Add(1)
	go b.manage()

	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *wireguardTcpBind) Close() error {
	b.mu.Lock()
	if !b.open || b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	close(b.closeCh)
	c := b.conn
	b.conn = nil
	b.mu.Unlock()

	if c != nil {
		c.Close()
	}

	// Wait for the manager (and its read loop) to exit so we don't leak
	// goroutines or sockets across reopen.
	b.wg.Wait()

	b.mu.Lock()
	b.open = false
	b.mu.Unlock()
	return nil
}

func (b *wireguardTcpBind) SetMark(mark uint32) error { return nil }

func (b *wireguardTcpBind) BatchSize() int { return 1 }

func (b *wireguardTcpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	ep := &tcpEndpoint{addr: addr}
	b.endpoint.Store(ep)
	return ep, nil
}

// Send frames every datagram in bufs and writes it to the current TCP
// connection. Writes are serialized under b.mu so concurrent WireGuard sends
// cannot interleave frames. A write failure tears down the connection so the
// manager goroutine reconnects.
func (b *wireguardTcpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return net.ErrClosed
	}
	c := b.conn
	if c == nil {
		// Not connected yet. Drop the datagram; WireGuard will retransmit
		// handshakes/keepalives once the connection is (re)established.
		return errTcpBindNotConnected
	}

	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		if err := writeFrame(c, buf); err != nil {
			// Tear down this connection so the manager dials a fresh one.
			c.Close()
			if b.conn == c {
				b.conn = nil
			}
			return err
		}
	}
	return nil
}

// receive is the single conn.ReceiveFunc handed to WireGuard. It delivers
// decapsulated payloads produced by the read loop.
func (b *wireguardTcpBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	// Prefer reporting closure over draining buffered payloads.
	select {
	case <-b.closeCh:
		return 0, net.ErrClosed
	default:
	}

	select {
	case <-b.closeCh:
		return 0, net.ErrClosed
	case payload := <-b.recvCh:
		sizes[0] = copy(bufs[0], payload)
		if ep := b.endpoint.Load(); ep != nil {
			eps[0] = ep
		}
		return 1, nil
	}
}

// manage owns the lifecycle of the outbound TCP connection: dial, run the read
// loop, and reconnect with bounded backoff. Exactly one of these runs per Open.
func (b *wireguardTcpBind) manage() {
	defer b.wg.Done()

	backoff := tcpReconnectMinBackoff
	for {
		if b.isClosed() {
			return
		}

		c, err := net.DialTimeout("tcp", b.address, tcpDialTimeout)
		if err != nil {
			b.logger.WithError(err).Warn("wireguard_tcp.dial_failed")
			if !b.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		b.logger.Info("wireguard_tcp.connected")
		// Reset backoff after a successful connection so a single drop reconnects
		// promptly, but a flapping gateway still backs off.
		backoff = tcpReconnectMinBackoff
		b.setConn(c)

		// Block reading frames until the connection fails or is closed.
		b.readLoop(c)
		b.clearConn(c)

		if b.isClosed() {
			return
		}
		if !b.sleep(backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// readLoop decapsulates frames from c and forwards payloads to the receive func.
// It returns when the connection fails, is closed, or the bind is closing.
func (b *wireguardTcpBind) readLoop(c net.Conn) {
	for {
		payload, err := readFrame(c)
		if err != nil {
			if !b.isClosed() {
				b.logger.WithError(err).Warn("wireguard_tcp.read_failed")
			}
			return
		}
		if len(payload) == 0 {
			continue // ignore empty frames
		}
		select {
		case b.recvCh <- payload:
		case <-b.closeCh:
			return
		}
	}
}

func (b *wireguardTcpBind) setConn(c net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		c.Close()
		return
	}
	b.conn = c
}

func (b *wireguardTcpBind) clearConn(c net.Conn) {
	b.mu.Lock()
	if b.conn == c {
		b.conn = nil
	}
	b.mu.Unlock()
	c.Close()
}

func (b *wireguardTcpBind) isClosed() bool {
	select {
	case <-b.closeCh:
		return true
	default:
		return false
	}
}

// sleep waits for d, returning false early if the bind is closed.
func (b *wireguardTcpBind) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-b.closeCh:
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	next := d * 2
	if next > tcpReconnectMaxBackoff {
		return tcpReconnectMaxBackoff
	}
	return next
}

// tcpTransportAddress returns the gateway's TCP address (host:port) for the TCP
// transport, reusing the first WireGuard peer endpoint as-is. The gateway listens
// for TCP on the same host:port it uses for UDP.
func (config *WireguardBase) tcpTransportAddress() (string, error) {
	for i := range config.Peers {
		if config.Peers[i].resolvedEndpoint != "" {
			return config.Peers[i].resolvedEndpoint, nil
		}
		if config.Peers[i].Endpoint != "" {
			return config.Peers[i].Endpoint, nil
		}
	}
	return "", fmt.Errorf("tcp transport enabled but no wireguard peer endpoint is configured")
}
