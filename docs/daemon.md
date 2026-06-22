# Dumbpipe daemon

The daemon runs many named tunnels over a single iroh endpoint, driven by a
config file. It is the multi-tunnel counterpart to the single-purpose
`listen-tcp` and `connect-tcp` subcommands: instead of one process per tunnel,
one daemon serves any number of incoming and outgoing tunnels from one endpoint
(one identity).

```
dumbpipe daemon [-c <config.toml>]
```

## Config file

The config path is taken from `-c/--config` if given, and otherwise defaults to
`<data_dir>/dumbpipe/daemon/daemon.toml`, where `<data_dir>` is the platform
data directory (`~/.local/share` on Linux, `~/Library/Application Support` on
macOS; see the [`dirs`](https://crates.io/crates/dirs) crate).

The config has two kinds of entries, each repeatable:

```toml
# Expose a local TCP port that forwards to a remote endpoint under a name.
[[connect]]
remote = "<endpoint-id-or-ticket>"
name   = "boo"
addr   = "localhost:13414"

# Forward incoming streams with a given name to a local TCP backend.
[[accept]]
name = "foo"
addr = "localhost:31231"

[[accept]]
name = "bar"
addr = "10.0.0.3:80"
```

A `connect` entry binds `addr` as a local TCP listener. Every accepted socket is
forwarded to the endpoint `remote`, tagging the stream with `name`. An `accept`
entry registers a backend: an incoming stream tagged with `name` is forwarded to
that entry's `addr`. The two sides are wired together by matching names, so the
`connect` side and the `accept` side of one tunnel must agree on the name.

`addr` values are resolved at bind and connect time, so host names such as
`localhost:13414` work as well as literal socket addresses.

### The `remote` field

`remote` accepts either form:

- A bare endpoint id (hex or base32). The remote is then resolved through
  discovery, exactly like a dumbpipe short ticket.
- A full endpoint ticket that also carries relay and direct-address hints. The
  hints are seeded into the endpoint's address book (see
  [Connection handling](#connection-handling)), so the remote can be reached
  without waiting on discovery.

## Secret key

The daemon uses a stable identity so that its endpoint id does not change across
restarts. The secret key is resolved in this order:

1. The `IROH_SECRET` environment variable (hex or base32), if set.
2. `<data_dir>/dumbpipe/daemon/secret.key`, a 32-byte lowercase hex key.
3. Otherwise a fresh key is generated and written to `secret.key` for next time.

## Named handshake

A single endpoint multiplexes several tunnels, so each stream must say which
backend it is for. On a fresh bidi stream the connecting side writes a named
handshake before any data:

```
"named" (5 bytes) || name length (u32, big-endian) || name (UTF-8)
```

The accepting side reads the prefix, the length (capped to bound allocation),
and the name, then routes the stream to the matching `accept` backend. A stream
whose name has no matching backend is dropped with a warning. This handshake
replaces the plain `"hello"` handshake that the single-tunnel subcommands use.

## Connection handling

The connect side reuses one iroh connection per remote across TCP streams,
rather than dialing afresh for every connection. Connections are managed by a
shared pool keyed by endpoint id; a connection is kept warm for a short idle
period and reused by later streams, then closed once unused. If a connect
attempt fails, it is retried once, which covers a transient discovery or relay
hiccup.

Because the pool connects by endpoint id, relay and direct-address hints from a
ticket-form `remote` are registered with the endpoint as a static address
lookup at startup. This runs alongside the default discovery, so a ticket's
hints let the daemon connect immediately while bare ids fall back to discovery.

## Shutdown

The daemon runs until interrupted with ctrl-c, at which point it stops accepting
new connections, cancels its listeners, and closes the endpoint.

## Example

Forward a web server running on one machine to a local port on another, plus a
second tunnel for SSH, all from one daemon on each side.

On the server machine, `server.toml`:

```toml
[[accept]]
name = "web"
addr = "localhost:3000"

[[accept]]
name = "ssh"
addr = "localhost:22"
```

```
dumbpipe daemon -c server.toml
# logs: daemon endpoint bound endpoint_id=<id>
```

On the client machine, `client.toml` (using the server's endpoint id):

```toml
[[connect]]
remote = "<server-endpoint-id>"
name   = "web"
addr   = "127.0.0.1:8080"

[[connect]]
remote = "<server-endpoint-id>"
name   = "ssh"
addr   = "127.0.0.1:2222"
```

```
dumbpipe daemon -c client.toml
```

The client can now reach the server's web server at `127.0.0.1:8080` and its
SSH server at `127.0.0.1:2222`, both over a single reused iroh connection.
