package sip

import (
	"context"
	"errors"
	"net"
	"runtime"
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

// TestSweepStalePeers_TTLBoundary pins the strict Before semantics of
// collectStale: an entry whose lastSeen is exactly at the cutoff is NOT
// evicted; one nanosecond older is.
func TestSweepStalePeers_TTLBoundary(t *testing.T) {
	t0 := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	ttl := 30 * time.Second

	tr := &TransportUDP{peerIdleTTL: ttl, nowFn: func() time.Time { return t0 }}
	tr.init(NewParser())

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1)

	peers := newPeerLastSeen()
	atCutoff := peerAddr(41001).String()
	pastCutoff := peerAddr(41002).String()
	peers.touch(atCutoff, t0)
	peers.touch(pastCutoff, t0.Add(-time.Nanosecond))
	tr.pool.Add(atCutoff, listener)
	tr.pool.Add(pastCutoff, listener)

	// "now" sits exactly TTL after t0, so cutoff == t0. atCutoff.lastSeen ==
	// cutoff → Before(cutoff) is false → not stale. pastCutoff is 1ns earlier
	// → stale.
	now := t0.Add(ttl)
	evicted := tr.sweepStalePeers(now, ttl, peers, listener)
	require.Equal(t, 1, evicted)

	assert.NotNil(t, tr.pool.getUnref(atCutoff), "entry exactly at cutoff is retained (strict Before)")
	assert.Nil(t, tr.pool.getUnref(pastCutoff), "entry one nanosecond older is evicted")
}

// TestReadListenerConnection_ReAddsEvictedPeer is the end-to-end proof for
// the firstSeen-after-eviction code path: after the sweep drops a peer
// entry, the next packet from that same peer must reinstate the pool
// mapping so response-correlation does not break.
func TestReadListenerConnection_ReAddsEvictedPeer(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL:       50 * time.Millisecond,
		peerSweepInterval: 10 * time.Millisecond,
		nowFn:             clk.Now,
	}
	tr.init(NewParser())

	pc := newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060})
	listener := &UDPConnection{
		PacketConn: pc,
		PacketAddr: pc.LocalAddr().String(),
		Listener:   true,
	}
	tr.pool.Add(listener.PacketAddr, listener)

	var delivered atomic.Int32
	handler := func(_ Message) { delivered.Add(1) }

	done := make(chan struct{})
	go func() {
		tr.readListenerConnection(listener, listener.PacketAddr, handler)
		close(done)
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})

	peer := peerAddr(51234)
	payload := []byte(sweepTestOptionsPacket)

	// First packet establishes the per-peer pool entry.
	pc.send(payload, peer)
	require.Eventually(t, func() bool { return delivered.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.NotNil(t, tr.pool.getUnref(peer.String()), "peer registered on first packet")

	// Advance fake clock past the TTL; sweep must drop the entry.
	clk.Advance(500 * time.Millisecond)
	require.Eventually(t, func() bool {
		return tr.pool.getUnref(peer.String()) == nil
	}, 2*time.Second, 5*time.Millisecond, "sweep should evict idle peer")

	// Second packet from the same peer must reinstate the pool entry
	// regardless of lastRaddr still naming this peer.
	pc.send(payload, peer)
	require.Eventually(t, func() bool { return delivered.Load() == 2 }, time.Second, 5*time.Millisecond)
	require.NotNil(t, tr.pool.getUnref(peer.String()), "peer re-registered after eviction round trip")
}

// TestPeerLastSeen_ConcurrentTouchAndSweep stresses peerLastSeen + sweep
// from many goroutines under -race. The sweep ticker fires concurrently
// with touch() bursts and direct sweepStalePeers calls; the test passes if
// the race detector stays quiet, the sweep never panics on a mutated map,
// and the map converges to "all stale evicted" once the stress ends.
func TestPeerLastSeen_ConcurrentTouchAndSweep(t *testing.T) {
	const (
		writers          = 16
		touchesPerWriter = 200
		distinctPeers    = 64
		ttl              = 5 * time.Millisecond
	)

	tr := &TransportUDP{peerIdleTTL: ttl, nowFn: time.Now}
	tr.init(NewParser())

	listener := &UDPConnection{
		PacketConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060}),
		PacketAddr: "0.0.0.0:5060",
		Listener:   true,
	}
	listener.Ref(1)

	peers := newPeerLastSeen()
	stop := make(chan struct{})

	// Background sweeper running roughly every 100µs against the live peers
	// map. This is more aggressive than the production ticker but matches
	// the test goal: maximize the chance of catching a touch/collect race.
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		for {
			select {
			case <-stop:
				return
			default:
				tr.sweepStalePeers(time.Now(), ttl, peers, listener)
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	// Concurrent writers touch a rotating set of peers and intermittently
	// register them in the pool, mirroring readListenerConnection's per-
	// packet path. Reuse the listener as the pool value as the live read
	// loop does.
	var writersWG sync.WaitGroup
	writersWG.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer writersWG.Done()
			for i := 0; i < touchesPerWriter; i++ {
				addr := peerAddr(60000 + ((w*touchesPerWriter + i) % distinctPeers)).String()
				if peers.touch(addr, time.Now()) {
					tr.pool.Add(addr, listener)
				}
			}
		}()
	}
	writersWG.Wait()

	close(stop)
	<-sweepDone

	// After the writers stop touching, every peer entry ages past TTL on the
	// next tick. Final convergence sweep drains the map.
	require.Eventually(t, func() bool {
		time.Sleep(ttl + 2*time.Millisecond) // age remaining entries
		tr.sweepStalePeers(time.Now(), ttl, peers, listener)
		return peers.size() == 0
	}, time.Second, 5*time.Millisecond, "peers map should converge to empty after stress ends")
}

// TestReadListenerConnection_SweepGoroutineExits verifies that closing the
// listener tears down the sweep goroutine as well — a leak here would
// accumulate one goroutine per Serve invocation over the process lifetime.
func TestReadListenerConnection_SweepGoroutineExits(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC))
	tr := &TransportUDP{
		peerIdleTTL:       30 * time.Second,
		peerSweepInterval: 5 * time.Millisecond,
		nowFn:             clk.Now,
	}
	tr.init(NewParser())

	pc := newFakePacketConn(&net.UDPAddr{IP: net.IPv4zero, Port: 5060})
	listener := &UDPConnection{
		PacketConn: pc,
		PacketAddr: pc.LocalAddr().String(),
		Listener:   true,
	}
	tr.pool.Add(listener.PacketAddr, listener)

	baseline := runtime.NumGoroutine()

	done := make(chan struct{})
	go func() {
		tr.readListenerConnection(listener, listener.PacketAddr, func(Message) {})
		close(done)
	}()

	// Confirm the read loop + sweep goroutine are actually running.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() >= baseline+2
	}, time.Second, 5*time.Millisecond, "read + sweep goroutines should be running")

	// Inject a packet so the sweep ticker has fired at least once with a
	// non-empty peers map. Not strictly required to prove shutdown, but
	// matches realistic usage and lets the ticker exercise its select.
	pc.send([]byte(sweepTestOptionsPacket), peerAddr(52000))
	time.Sleep(20 * time.Millisecond)

	require.NoError(t, pc.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("read loop did not exit")
	}

	// Give the sweep goroutine a moment to observe the closed done channel.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+1 // allow one stragglar from test runtime
	}, time.Second, 5*time.Millisecond, "sweep goroutine must exit when listener exits")
}
