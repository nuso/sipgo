# SIP stack in GO

This SIP stack for RFC: 

https://datatracker.ietf.org/doc/html/rfc3261


Stack:
- Encoding/Decoding with `Parser` optimized for fast parsing
- Transport Layer and support for different protocols
- Transaction Layer with transaction sessions managing and state machine


## Parser

Parser by default parses set of headers that are mostly present in messages. From,To,Via,Cseq,Content-Type,Content-Length...
This headers are accessible via fast reference `msg.Via()`, `msg.From()`...

This can be configured using `WithHeadersParsers` and reducing this to increase performance. 
SIP stack in case needed will use fast reference and lazy parsing.


## Transport Layer

`TransportLayer` runs the UDP / TCP / TLS / WS / WSS listeners that drive the
SIP stack. Options are passed to `NewTransportLayer` and apply to all
configured protocols.

### UDP peer-pool eviction (opt-in)

A long-lived UDP listener (one that never exits `ServeUDP` for the lifetime
of the process) accumulates one `connectionPool` entry per distinct inbound
source address. Under normal operation the cardinality is tiny, but under
adversarial source-port churn the map grows unbounded.

```go
tp := sip.NewTransportLayer(
    net.DefaultResolver,
    sip.NewParser(),
    nil,
    sip.WithTransportLayerUDPPeerIdleTTL(5*time.Minute),
)
```

Behavior:

- A peer's pool entry is evicted on the next sweep after `ttl` of idleness.
- The sweep is skipped when the listener connection has an elevated
  refcount (a transaction is in flight). For UDP listeners the refcount is
  shared across every per-peer mapping, so this is a conservative
  per-listener gate, not a per-peer one — the TTL behaves as a lower
  bound while idle rather than an upper bound under sustained load.
- Default (`ttl == 0`) preserves the pre-existing accumulate-until-exit
  behavior.

### Monitoring pool cardinality

`(*TransportLayer).UDPPoolSize()` returns the current number of entries in
the UDP connection pool (listener self-entry + per-peer mappings + any
client-dialed connections). Expose it as a gauge to keep eviction tuning
observable.