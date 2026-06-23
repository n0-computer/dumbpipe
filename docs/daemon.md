# Dumbpipe daemon

The daemon runs many named tunnels over a single iroh endpoint, driven by a
config file. It is the multi-tunnel counterpart to the single-purpose
`listen-tcp` and `connect-tcp` subcommands: instead of one process per tunnel,
one daemon serves any number of incoming and outgoing tunnels from one endpoint
(one identity).

```
dumbpipe daemon [-c <config.toml>] run
dumbpipe daemon [-c <config.toml>] install | uninstall | start | stop | status
dumbpipe daemon [-c <config.toml>] accept  <name> <addr> [--token <t>] [--secure]
dumbpipe daemon [-c <config.toml>] connect <remote>:<name> <addr> [--token <t>]
dumbpipe daemon [-c <config.toml>] show
```

A subcommand is required; `dumbpipe daemon` with none prints help.

- `run` runs the daemon in the foreground.
- `install` / `uninstall` / `start` / `stop` / `status` manage the daemon as a
  user-level service (see [Running as a service](#running-as-a-service)).
- `accept` / `connect` edit the config file and do not run anything.
- `show` prints the configured tunnels.

## Config file

The config path is taken from `-c/--config` if given, and otherwise defaults to
`<data_dir>/dumbpipe/daemon/daemon.toml`, where `<data_dir>` is the platform
data directory (`~/.local/share` on Linux, `~/Library/Application Support` on
macOS; see the [`dirs`](https://crates.io/crates/dirs) crate). `run` creates an
empty config there if none exists rather than failing.

```toml
# Watch this file and apply changes while running (see Reloading).
reload = true

# Expose a local TCP port that forwards to a remote endpoint under a name.
[[connect]]
remote = "<endpoint-id-or-ticket>"
name   = "boo"
addr   = "localhost:13414"
token  = "optional-token"   # presented to the remote accept tunnel

# Forward incoming streams with a given name to a local TCP backend.
[[accept]]
name  = "foo"
addr  = "localhost:31231"
token = "optional-token"    # required from the connecting side
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

### Tokens

A tunnel can be protected with a shared token. When an `accept` entry has a
`token`, an incoming stream is forwarded only if the connecting side presents
the same token; otherwise the stream is dropped. An `accept` entry without a
token accepts any matching stream. The token travels inside the per-stream
[header](#stream-header), which is carried over the encrypted iroh connection.

## Editing the config from the command line

The `accept` and `connect` subcommands append an entry to the config file
(creating it if needed), so the config can be built up without editing TOML by
hand. With [reloading](#reloading) on, a running daemon picks the change up
immediately.

```
# Add an accept backend named "web", protected by a generated token.
dumbpipe daemon accept web localhost:3000 --secure
# added accept web -> localhost:3000
# token: MZUW4Z3FOJSWG5DBNVSXG43F

# Or set the token explicitly.
dumbpipe daemon accept ssh localhost:22 --token hunter2

# Add a connect tunnel. The first argument is remote:name.
dumbpipe daemon connect <remote-id-or-ticket>:web 127.0.0.1:8080 --token MZUW4Z3FOJSWG5DBNVSXG43F
```

`--secure` generates a random token of 16 base32-encoded bytes and prints it.
`--secure` and `--token` are mutually exclusive.

## Running as a service

The daemon can install itself as a user-level service via
[`service-manager`](https://crates.io/crates/service-manager), which uses the
platform's native service manager (systemd user units on Linux, launchd on
macOS, and so on):

```
dumbpipe daemon -c config.toml install   # install a service that runs `daemon run -c <config>`
dumbpipe daemon start                     # start it
dumbpipe daemon status                    # not installed | stopped | running
dumbpipe daemon stop                      # stop it
dumbpipe daemon uninstall                 # remove it
```

`install` records the absolute config path so the service finds it regardless of
its working directory, and enables start at login. The service runs `daemon run`
in the foreground under the service manager. No elevated permissions are
required: the service is installed at the user level (a systemd user unit, a
launchd user agent, and so on).

User-level services are not supported on every platform; failures print the
underlying service-manager error. On macOS in particular, launchd only loads a
user agent inside a GUI login session, so `install` over SSH fails: run it from a
Terminal in the desktop session.

## Reloading

When `reload` is `true` (the default, and what the subcommands write), the
daemon watches the config file with [`notify`](https://crates.io/crates/notify)
and applies changes while running:

- accept routes are swapped in atomically;
- connect tunnels are reconciled by local address: tunnels that disappeared or
  changed are stopped, and newly added ones are bound and started;
- relay and address hints for new remotes are registered.

A bad edit (unparseable file, a remote that fails to parse, an address that
fails to bind) is logged and skipped; the daemon keeps running with the entries
that are still valid. Set `reload = false` to load the config once at startup
and ignore later changes.

## Secret key

The daemon uses a stable identity so that its endpoint id does not change across
restarts. The secret key is resolved in this order:

1. The `IROH_SECRET` environment variable (hex or base32), if set.
2. `<data_dir>/dumbpipe/daemon/secret.key`, a 32-byte lowercase hex key.
3. Otherwise a fresh key is generated and written to `secret.key` for next time.

## Output

On startup, after the endpoint comes online, the daemon prints to stdout:

- `short addr:` followed by its endpoint id, as hex;
- `long addr:` followed by its ticket, in the same format the `remote` field
  accepts, so it can be pasted into a connecting daemon's config;
- one line per configured tunnel, the same listing `daemon show` prints.

```
short addr: f2e16a92c17a40ceb7bbb6e6f216ad98f59f7708f32ff24bf8ed6335c908bb1d
 long addr: endpointadzoc2usyf5ebtvxxo3on4qwvwmplh3xbdzs74sl7dwwgnojbc5r2ay...
connect 127.0.0.1:8080 -> <remote>:web [token]
accept web -> localhost:3000 [token]
accept ssh -> localhost:22
```

A `connect` line reads `connect <local-addr> -> <remote>:<name>`, an `accept`
line reads `accept <name> -> <backend-addr>`, and `[token]` marks a
token-protected tunnel. The id and the ticket are both valid `remote` values;
the ticket additionally carries the relay and address hints.

`daemon show` prints the same tunnel listing without starting the daemon.

## Logging

The daemon logs lifecycle events (endpoint binding, tunnel listeners, reloads)
at `info`, and per-forward connect/disconnect events inside tracing spans:

```
incoming{remote=f198fe07e6}:tcp{name=foo target=localhost:31231}: connected
incoming{remote=f198fe07e6}:tcp{name=foo target=localhost:31231}: disconnected
outgoing{remote=69696f31c6}:tcp{name=foo target=127.0.0.1:58084}: connected
outgoing{remote=69696f31c6}:tcp{name=foo target=127.0.0.1:58084}: disconnected
```

An accepted iroh connection runs in an `incoming{remote}` span and each
forwarded stream in a child `tcp{name, target}` span, where `target` is the
backend address; the connect side mirrors this with `outgoing{remote}` and
`tcp{name, target}`, where `target` is the local client. `remote` is the short
endpoint id.

When `RUST_LOG` is unset the daemon defaults to `dumbpipe=info,iroh=info`; set
`RUST_LOG` to override (for example `RUST_LOG=dumbpipe=debug`).

## Stream header

The daemon speaks its own ALPN, distinct from the single-tunnel dumbpipe
protocol. A single endpoint multiplexes several tunnels, so each stream begins
with a header that says which backend it is for and carries the optional token.
On a fresh bidi stream the connecting side writes, before any data:

```
header length (u32, big-endian) || postcard-encoded { name, token }
```

The accepting side reads the length (capped to bound allocation) and decodes the
header, routes the stream to the matching `accept` backend, and checks the token.
A stream whose name has no matching backend, or whose token does not match, is
dropped with a warning.

## Connection handling

The connect side reuses one iroh connection per remote across TCP streams,
rather than dialing afresh for every connection. Connections are managed by a
shared pool keyed by endpoint id; a connection is kept warm for a short idle
period and reused by later streams, then closed once unused. If a connect
attempt fails, it is retried once, which covers a transient discovery or relay
hiccup.

Because the pool connects by endpoint id, relay and direct-address hints from a
ticket-form `remote` are registered with the endpoint as a static address
lookup. This runs alongside the default discovery, so a ticket's hints let the
daemon connect immediately while bare ids fall back to discovery.

## Shutdown

The daemon runs until interrupted with ctrl-c, at which point it stops accepting
new connections, cancels its listeners, and closes the endpoint.

## Example

Forward a web server and an SSH server from one machine to local ports on
another, all from one daemon on each side.

On the server machine:

```
dumbpipe daemon -c server.toml accept web localhost:3000
dumbpipe daemon -c server.toml accept ssh localhost:22 --secure
# token: MZUW4Z3FOJSWG5DBNVSXG43F
dumbpipe daemon -c server.toml run
# short addr: <id>
#  long addr: <ticket>
```

On the client machine, using the server's id or ticket:

```
dumbpipe daemon -c client.toml connect <server>:web 127.0.0.1:8080
dumbpipe daemon -c client.toml connect <server>:ssh 127.0.0.1:2222 --token MZUW4Z3FOJSWG5DBNVSXG43F
dumbpipe daemon -c client.toml run
```

The client can now reach the server's web server at `127.0.0.1:8080` and its SSH
server at `127.0.0.1:2222`, both over a single reused iroh connection. Because
the configs were built with the subcommands, `reload` is on, so the tunnels
added on each side take effect without restarting the daemons.
