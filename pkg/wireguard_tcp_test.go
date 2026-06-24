package pkg

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
)

func quietLogger() *log.Entry {
	l := log.New()
	l.SetOutput(io.Discard)
	return log.NewEntry(l)
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello wireguard"),
		{0x00},
		bytes.Repeat([]byte{0xAB}, 1500),
		bytes.Repeat([]byte{0xCD}, tcpMaxFramePayload),
	}

	for _, payload := range cases {
		buf := &bytes.Buffer{}
		if err := writeFrame(buf, payload); err != nil {
			t.Fatalf("writeFrame(%d bytes) failed: %v", len(payload), err)
		}

		// a frame is exactly 2 length bytes + the payload
		if buf.Len() != 2+len(payload) {
			t.Fatalf("expected framed length %d, got %d", 2+len(payload), buf.Len())
		}

		got, err := readFrame(buf)
		if err != nil {
			t.Fatalf("readFrame failed: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d bytes", len(got), len(payload))
		}
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0x01}, tcpMaxFramePayload+1)
	buf := &bytes.Buffer{}

	err := writeFrame(buf, payload)
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("expected errFrameTooLarge, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversized frame should not write any bytes, wrote %d", buf.Len())
	}
}

func TestReadFrameEmptyPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := writeFrame(buf, nil); err != nil {
		t.Fatalf("writeFrame(nil) failed: %v", err)
	}
	got, err := readFrame(buf)
	if err != nil {
		t.Fatalf("readFrame failed: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil payload for empty frame, got %d bytes", len(got))
	}
}

// fakeGateway is a minimal TCP server that stands in for the gateway's TCP
// WireGuard listener. It hands accepted connections back to the test.
type fakeGateway struct {
	ln    net.Listener
	conns chan net.Conn
}

func startFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake gateway: %v", err)
	}
	g := &fakeGateway{ln: ln, conns: make(chan net.Conn, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			g.conns <- c
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return g
}

func (g *fakeGateway) address() string { return g.ln.Addr().String() }

func (g *fakeGateway) accept(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-g.conns:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for broker to connect over TCP")
		return nil
	}
}

// sendUntilConnected retries Send until the bind has an established connection,
// tolerating the brief window between dial and connection registration. Exactly
// one frame is written (failed attempts before connection write nothing).
func sendUntilConnected(t *testing.T, b *wireguardTcpBind, payload []byte, ep conn.Endpoint) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := b.Send([][]byte{payload}, ep)
		if err == nil {
			return
		}
		if !errors.Is(err, errTcpBindNotConnected) {
			t.Fatalf("unexpected Send error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("broker never established TCP connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWireguardTcpBindSendsFramedPackets(t *testing.T) {
	gateway := startFakeGateway(t)

	bind := NewWireguardTcpBind(gateway.address(), quietLogger())
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer bind.Close()

	ep, err := bind.ParseEndpoint(gateway.address())
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}

	gwConn := gateway.accept(t)
	defer gwConn.Close()

	payload := []byte("framed wireguard datagram")
	sendUntilConnected(t, bind, payload, ep)

	gwConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := readFrame(gwConn)
	if err != nil {
		t.Fatalf("gateway failed to read framed packet: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("gateway received %q, want %q", got, payload)
	}
}

func TestWireguardTcpBindReceivesFramedPackets(t *testing.T) {
	gateway := startFakeGateway(t)

	bind := NewWireguardTcpBind(gateway.address(), quietLogger())
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer bind.Close()

	gwConn := gateway.accept(t)
	defer gwConn.Close()

	payload := []byte("inbound wireguard datagram")
	if err := writeFrame(gwConn, payload); err != nil {
		t.Fatalf("gateway failed to write framed packet: %v", err)
	}

	type recvResult struct {
		n    int
		size int
		buf  []byte
		err  error
	}
	resultCh := make(chan recvResult, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := []conn.Endpoint{nil}
		n, err := fns[0](bufs, sizes, eps)
		resultCh <- recvResult{n: n, size: sizes[0], buf: bufs[0], err: err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("receive func returned error: %v", res.err)
		}
		if res.n != 1 {
			t.Fatalf("expected 1 packet, got %d", res.n)
		}
		if !bytes.Equal(res.buf[:res.size], payload) {
			t.Fatalf("received %q, want %q", res.buf[:res.size], payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for decapsulated packet")
	}
}

func TestWireguardTcpBindReconnects(t *testing.T) {
	gateway := startFakeGateway(t)

	bind := NewWireguardTcpBind(gateway.address(), quietLogger())
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer bind.Close()

	ep, err := bind.ParseEndpoint(gateway.address())
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}

	// first connection
	conn1 := gateway.accept(t)
	sendUntilConnected(t, bind, []byte("before drop"), ep)

	// simulate the gateway dropping the connection
	conn1.Close()

	// the broker should dial a fresh connection with bounded backoff
	conn2 := gateway.accept(t)
	defer conn2.Close()

	payload := []byte("after reconnect")
	sendUntilConnected(t, bind, payload, ep)

	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := readFrame(conn2)
	if err != nil {
		t.Fatalf("failed to read after reconnect: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("after reconnect received %q, want %q", got, payload)
	}
}

func TestWireguardTcpBindCloseUnblocksReceive(t *testing.T) {
	gateway := startFakeGateway(t)

	bind := NewWireguardTcpBind(gateway.address(), quietLogger())
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := []conn.Endpoint{nil}
		_, err := fns[0](bufs, sizes, eps)
		errCh <- err
	}()

	// give the receive func a moment to block, then close
	time.Sleep(20 * time.Millisecond)
	if err := bind.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed after Close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive func did not return after Close")
	}
}
