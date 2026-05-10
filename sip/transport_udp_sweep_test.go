package sip

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimal SIP OPTIONS payload used as packet body in sweep tests. The parser
// only needs a well-formed start line + minimum headers to dispatch.
const sweepTestOptionsPacket = "OPTIONS sip:test@127.0.0.1 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:0;branch=z9hG4bK-sweep\r\n" +
	"From: <sip:probe@127.0.0.1>;tag=1\r\n" +
	"To: <sip:test@127.0.0.1>\r\n" +
	"Call-ID: sweep-test\r\n" +
	"CSeq: 1 OPTIONS\r\n" +
	"Max-Forwards: 70\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

// packetEvent is one inbound packet on a fakePacketConn.
type packetEvent struct {
	data []byte
	addr *net.UDPAddr
}

// fakePacketConn is a deterministic net.PacketConn for the sweep tests. Tests
// queue packetEvents via send() and close() to terminate ReadFrom.
type fakePacketConn struct {
	local  net.Addr
	inbox  chan packetEvent
	closed chan struct{}
	once   sync.Once
}

func newFakePacketConn(local net.Addr) *fakePacketConn {
	return &fakePacketConn{
		local:  local,
		inbox:  make(chan packetEvent, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakePacketConn) send(data []byte, addr *net.UDPAddr) {
	select {
	case f.inbox <- packetEvent{data: data, addr: addr}:
	case <-f.closed:
	}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case ev := <-f.inbox:
		n := copy(p, ev.data)
		return n, ev.addr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakePacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (f *fakePacketConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr             { return f.local }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// fakeClock is a thread-safe, manually-advanced clock for sweep tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// peerAddr builds a net.UDPAddr suitable as a fake source for rotating-port tests.
func peerAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: port}
}

// TestSweepStalePeers_EvictsIdleEntries exercises the eviction unit directly
// without standing up a read loop. The sweep should drop addresses whose
// lastSeen falls outside the TTL window.
func TestSweepStalePeers_EvictsIdleEntries(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL: 30 * time.Second,
		nowFn:       clk.Now,
	}
	tr.init(NewParser())

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1) // baseline ref the read loop normally establishes via pool.Add

	peers := newPeerLastSeen()

	// Three peers: two idle, one fresh. All registered in the pool the same way
	// readListenerConnection would after a first-seen packet.
	idleA := peerAddr(40001).String()
	idleB := peerAddr(40002).String()
	fresh := peerAddr(40003).String()

	peers.touch(idleA, clk.Now())
	peers.touch(idleB, clk.Now())
	tr.pool.Add(idleA, listener)
	tr.pool.Add(idleB, listener)

	clk.Advance(35 * time.Second) // age idleA, idleB past TTL
	peers.touch(fresh, clk.Now())
	tr.pool.Add(fresh, listener)

	evicted := tr.sweepStalePeers(clk.Now(), tr.peerIdleTTL, peers, listener)
	require.Equal(t, 2, evicted, "two idle peers should be evicted")

	assert.Equal(t, 1, peers.size(), "fresh peer remains in lastSeen map")
	assert.Nil(t, tr.pool.getUnref(idleA), "idleA removed from pool")
	assert.Nil(t, tr.pool.getUnref(idleB), "idleB removed from pool")
	assert.NotNil(t, tr.pool.getUnref(fresh), "fresh peer retained in pool")
}

// TestSweepStalePeers_SkipsWhenListenerInFlight asserts the conservative
// short-circuit: if anything holds an extra reference to the listener
// connection (a transaction is mid-flight), the sweep does nothing this pass.
func TestSweepStalePeers_SkipsWhenListenerInFlight(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL: 30 * time.Second,
		nowFn:       clk.Now,
	}
	tr.init(NewParser())

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1) // baseline

	peers := newPeerLastSeen()
	idle := peerAddr(40010).String()
	peers.touch(idle, clk.Now())
	tr.pool.Add(idle, listener)

	clk.Advance(60 * time.Second)

	// Simulate an in-flight transaction holding a reference (Ref now == 2).
	listener.Ref(1)
	defer listener.Ref(-1)

	evicted := tr.sweepStalePeers(clk.Now(), tr.peerIdleTTL, peers, listener)
	assert.Zero(t, evicted, "must skip eviction while listener is referenced")
	assert.NotNil(t, tr.pool.getUnref(idle), "pool entry retained while in-flight")
	assert.Equal(t, 1, peers.size(), "lastSeen retained while in-flight")
}

// TestSweepStalePeers_DisabledWhenTTLZero pins the default-off behavior so
// existing consumers see no change unless they opt in.
func TestSweepStalePeers_DisabledWhenTTLZero(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{nowFn: clk.Now}
	tr.init(NewParser())
	require.Zero(t, tr.peerIdleTTL, "default TTL must be zero (disabled)")
	require.Zero(t, tr.peerSweepInterval, "no sweep interval derived when disabled")

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1)

	peers := newPeerLastSeen()
	addr := peerAddr(40020).String()
	peers.touch(addr, clk.Now())
	tr.pool.Add(addr, listener)

	clk.Advance(24 * time.Hour)

	evicted := tr.sweepStalePeers(clk.Now(), tr.peerIdleTTL, peers, listener)
	assert.Zero(t, evicted)
	assert.NotNil(t, tr.pool.getUnref(addr), "entry retained when TTL disabled")
}

// TestSweepStalePeers_TouchKeepsActivePeerAlive verifies that a peer whose
// lastSeen is updated within the TTL window survives the sweep.
func TestSweepStalePeers_TouchKeepsActivePeerAlive(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL: 30 * time.Second,
		nowFn:       clk.Now,
	}
	tr.init(NewParser())

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1)

	peers := newPeerLastSeen()
	keep := peerAddr(40030).String()
	peers.touch(keep, clk.Now())
	tr.pool.Add(keep, listener)

	clk.Advance(25 * time.Second)
	peers.touch(keep, clk.Now()) // refresh just before TTL
	clk.Advance(20 * time.Second)

	evicted := tr.sweepStalePeers(clk.Now(), tr.peerIdleTTL, peers, listener)
	assert.Zero(t, evicted, "refreshed peer must not be evicted within TTL")
	assert.NotNil(t, tr.pool.getUnref(keep))
}

// TestReadListenerConnection_EvictsRotatingSourcePorts is the integration
// test the BRI-15 ticket asks for: drive a fake PacketConn with packets from
// rotating source ports, advance a fake clock past the TTL, and assert the
// sweep goroutine wired into readListenerConnection drains the pool.
func TestReadListenerConnection_EvictsRotatingSourcePorts(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL:       50 * time.Millisecond, // fake-clock TTL
		peerSweepInterval: 10 * time.Millisecond, // real-time ticker cadence
		nowFn:             clk.Now,
	}
	tr.init(NewParser())

	// Count messages delivered to the handler so we can wait for ingestion
	// to complete before advancing the clock.
	var delivered atomic.Int32
	tr.parser = NewParser()

	pc := newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060})
	listener := &UDPConnection{
		PacketConn: pc,
		PacketAddr: pc.LocalAddr().String(),
		Listener:   true,
	}
	tr.pool.Add(listener.PacketAddr, listener)

	handler := func(_ Message) { delivered.Add(1) }

	done := make(chan struct{})
	go func() {
		tr.readListenerConnection(listener, listener.PacketAddr, handler)
		close(done)
	}()

	// Inject packets from rotating source ports. Each looks like a new peer
	// to the listener and gets its own pool entry.
	const peerCount = 12
	payload := []byte(sweepTestOptionsPacket)
	for i := 0; i < peerCount; i++ {
		pc.send(payload, peerAddr(50000+i))
	}

	// Wait for the read loop to ingest all packets.
	deadline := time.Now().Add(2 * time.Second)
	for delivered.Load() < peerCount && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.EqualValues(t, peerCount, delivered.Load(), "handler must receive every packet")

	// peerCount peer entries + the listener self-entry registered above.
	require.GreaterOrEqual(t, tr.pool.Size(), peerCount+1)

	// Advance the fake clock well past the TTL so the next sweep tick evicts.
	clk.Advance(500 * time.Millisecond)

	// Wait for the sweep goroutine to drain the per-peer entries. We only
	// expect the listener self-entry (PacketAddr) to remain.
	require.Eventually(t, func() bool {
		return tr.pool.Size() == 1
	}, 2*time.Second, 5*time.Millisecond, "sweep should evict all idle peer entries")

	// Tear down the read loop.
	_ = pc.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("read loop did not exit after fake conn close")
	}
}

// TestDefaultPeerSweepInterval guards the interval clamp that NewTransportLayer
// relies on so a poorly-tuned TTL cannot produce a hot-spin or hour-long gap.
func TestDefaultPeerSweepInterval(t *testing.T) {
	cases := []struct {
		ttl      time.Duration
		expected time.Duration
	}{
		{ttl: 100 * time.Millisecond, expected: time.Second},
		{ttl: 4 * time.Second, expected: time.Second},
		{ttl: 4 * time.Minute, expected: time.Minute},
		{ttl: time.Hour, expected: time.Minute},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.expected, defaultPeerSweepInterval(tc.ttl), "ttl=%s", tc.ttl)
	}
}

// TestNewTransportLayer_PropagatesUDPPeerIdleTTL pins the option wiring so a
// future refactor of NewTransportLayer cannot silently drop the TTL.
func TestNewTransportLayer_PropagatesUDPPeerIdleTTL(t *testing.T) {
	ttl := 90 * time.Second
	tp := NewTransportLayer(
		net.DefaultResolver,
		NewParser(),
		nil,
		WithTransportLayerUDPPeerIdleTTL(ttl),
	)
	t.Cleanup(func() {
		_ = tp.Close()
		// Drain any pending context so the test does not leak.
		_, _ = context.WithTimeout(context.Background(), 0)
	})
	require.Equal(t, ttl, tp.udp.peerIdleTTL)
	require.Equal(t, defaultPeerSweepInterval(ttl), tp.udp.peerSweepInterval)
}
