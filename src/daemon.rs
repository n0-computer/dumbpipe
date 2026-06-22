//! The dumbpipe daemon.
//!
//! The daemon runs many named tunnels over a single iroh endpoint, driven by a
//! TOML config file. It is the multi-tunnel counterpart to the single-purpose
//! `listen-tcp` / `connect-tcp` subcommands.
//!
//! A `[[connect]]` entry binds a local TCP port and forwards every accepted
//! socket to a remote endpoint under a name. A `[[accept]]` entry forwards
//! incoming named streams to a local TCP backend selected by that name. Because
//! one endpoint serves several tunnels, streams carry a name: see
//! [`dumbpipe::HANDSHAKE_NAMED`].

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use dumbpipe::{EndpointTicket, HANDSHAKE_NAMED};
use iroh::{address_lookup::MemoryLookup, EndpointAddr, EndpointId, SecretKey};
use iroh_util::connection_pool::{ConnectionPool, ConnectionRef, Options};
use n0_error::{bail_any, ensure_any, Result, StdResultExt};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, info, warn};

use crate::CommonArgs;

/// The maximum length of a tunnel name, in bytes.
///
/// The accepting side reads the name length from the wire before allocating the
/// name buffer, so this bound keeps a malicious or buggy peer from requesting a
/// huge allocation.
const MAX_NAME_LEN: usize = 1024;

/// How long the connection pool keeps an idle connection before closing it.
///
/// Connect tunnels reuse one iroh connection per remote across many TCP
/// streams; this keeps the connection warm between bursts of streams.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the connection pool waits for a connect to complete.
///
/// Connecting by endpoint id alone goes through discovery and a relay, so this
/// is generous compared to the pool's one-second default.
const POOL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Arguments for the `daemon` subcommand.
#[derive(Parser, Debug)]
pub struct DaemonArgs {
    /// Path to the daemon config file.
    ///
    /// Defaults to `<data_dir>/dumbpipe/daemon/daemon.toml`, where `data_dir`
    /// is the platform data directory (see the `dirs` crate).
    #[clap(short = 'c', long)]
    pub config: Option<PathBuf>,

    #[clap(flatten)]
    pub common: CommonArgs,
}

/// A remote endpoint reference in the config.
///
/// Accepts either a bare [`EndpointId`] (hex or base32) or a full
/// [`EndpointTicket`] string that also carries relay and address hints.
#[derive(Debug, Clone)]
struct Remote(EndpointAddr);

impl<'de> Deserialize<'de> for Remote {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // A ticket is the more specific form, so try it first and fall back to
        // a bare endpoint id.
        if let Ok(ticket) = EndpointTicket::from_str(&s) {
            return Ok(Self(ticket.endpoint_addr().clone()));
        }
        let id = EndpointId::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(EndpointAddr::from(id)))
    }
}

/// The daemon config, parsed from TOML.
#[derive(Debug, Clone, Deserialize)]
struct Config {
    /// Outgoing tunnels: local TCP port -> remote endpoint, under a name.
    #[serde(default)]
    connect: Vec<ConnectConfig>,
    /// Incoming tunnels: named stream -> local TCP backend.
    #[serde(default)]
    accept: Vec<AcceptConfig>,
}

/// A single `[[connect]]` entry.
#[derive(Debug, Clone, Deserialize)]
struct ConnectConfig {
    /// The remote endpoint to forward to.
    remote: Remote,
    /// The name sent in the handshake, used by the remote to route the stream.
    name: String,
    /// The local TCP address to listen on.
    addr: String,
}

/// A single `[[accept]]` entry.
#[derive(Debug, Clone, Deserialize)]
struct AcceptConfig {
    /// The name that selects this backend.
    name: String,
    /// The local TCP backend to forward matching streams to.
    addr: String,
}

/// Runs the daemon until interrupted with ctrl-c.
pub(crate) async fn run(args: DaemonArgs) -> Result<()> {
    let dir = daemon_dir()?;
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| dir.join("daemon.toml"));
    let config = load_config(&config_path)?;
    let secret_key = load_or_create_secret(&dir)?;

    // Seed a static address lookup with the relay and direct-address hints from
    // ticket-form remotes. The connection pool connects by endpoint id alone, so
    // without this those hints would be lost and only discovery could resolve the
    // remote. Bare-id remotes carry no hints and are left to discovery.
    let address_lookup = static_address_lookup(&config.connect);

    // The daemon always speaks the dumbpipe ALPN with the named handshake, so
    // it ignores `--custom-alpn`. It still honors the bind-address options.
    let endpoint = crate::create_endpoint(
        secret_key,
        &args.common,
        vec![dumbpipe::ALPN.to_vec()],
        address_lookup,
    )
    .await?;
    info!(endpoint_id = %endpoint.id(), "daemon endpoint bound");

    if timeout(crate::ONLINE_TIMEOUT, endpoint.online())
        .await
        .is_err()
    {
        warn!("failed to connect to the home relay");
    }

    if config.connect.is_empty() && config.accept.is_empty() {
        warn!("config has no [[connect]] or [[accept]] entries");
    }

    // Advertise this daemon's identity on stdout. The id (hex) and the ticket
    // are both valid `remote` values for a connecting daemon's config; the
    // ticket also carries the relay and address hints. Printed after `online`
    // so the ticket includes the home relay.
    println!("short addr: {}", endpoint.id());
    println!(" long addr: {}", EndpointTicket::new(endpoint.addr()));

    // Route incoming streams by name to a backend address. Reject duplicate
    // names up front: a duplicate would silently shadow an earlier backend.
    // List each configured accept backend on stdout.
    let mut routes: HashMap<String, String> = HashMap::new();
    for accept in &config.accept {
        if routes
            .insert(accept.name.clone(), accept.addr.clone())
            .is_some()
        {
            bail_any!("duplicate accept name {:?}", accept.name);
        }
        println!("accept {} -> {}", accept.name, accept.addr);
    }

    let token = CancellationToken::new();
    // Hold the tasks as abort-on-drop handles so they stop when `run` returns.
    let mut tasks: Vec<AbortOnDropHandle<()>> = Vec::new();

    // One pool shared by all connect tunnels. It reuses a single connection per
    // remote endpoint across TCP streams, keyed by endpoint id, instead of
    // dialing afresh for every stream.
    let pool = ConnectionPool::new(
        endpoint.clone(),
        dumbpipe::ALPN,
        Options {
            idle_timeout: POOL_IDLE_TIMEOUT,
            connect_timeout: POOL_CONNECT_TIMEOUT,
            ..Default::default()
        },
    );

    for connect in config.connect {
        // Bind before spawning so a bad address fails startup loudly instead of
        // disappearing into a background task's log.
        let listener = TcpListener::bind(&connect.addr)
            .await
            .with_std_context(|_| format!("failed to bind {}", connect.addr))?;
        info!(addr = %connect.addr, remote = %connect.remote.0.id, name = %connect.name, "connect listening");
        let pool = pool.clone();
        let token = token.child_token();
        tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
            if let Err(cause) = run_connect(pool, listener, connect, token).await {
                warn!("connect listener stopped: {cause}");
            }
        })));
    }

    if !routes.is_empty() {
        let endpoint = endpoint.clone();
        let routes = Arc::new(routes);
        let token = token.child_token();
        tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
            run_accept(endpoint, routes, token).await;
        })));
    }

    tokio::signal::ctrl_c().await.anyerr()?;
    info!("got ctrl-c, shutting down");
    token.cancel();
    endpoint.close().await;
    Ok(())
}

/// Builds a static address lookup from the connect remotes that carry hints.
///
/// Returns `None` if no remote has relay or direct-address hints, in which case
/// the endpoint relies on discovery alone.
fn static_address_lookup(connect: &[ConnectConfig]) -> Option<MemoryLookup> {
    let hints: Vec<EndpointAddr> = connect
        .iter()
        .map(|c| c.remote.0.clone())
        .filter(|addr| !addr.is_empty())
        .collect();
    (!hints.is_empty()).then(|| MemoryLookup::from_endpoint_info(hints))
}

/// Returns the daemon data directory, `<data_dir>/dumbpipe/daemon`.
fn daemon_dir() -> Result<PathBuf> {
    let Some(data_dir) = dirs::data_dir() else {
        bail_any!("could not determine the platform data directory");
    };
    Ok(data_dir.join("dumbpipe").join("daemon"))
}

/// Loads and parses the config file at `path`.
fn load_config(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_std_context(|_| format!("failed to read config {}", path.display()))?;
    toml::from_str(&contents)
        .with_std_context(|_| format!("failed to parse config {}", path.display()))
}

/// Loads the endpoint secret key, generating and persisting one if needed.
///
/// `IROH_SECRET` takes preference. Otherwise the key is read from
/// `<dir>/secret.key` (32-byte lowercase hex), and if that file does not exist
/// a fresh key is generated and written there.
fn load_or_create_secret(dir: &Path) -> Result<SecretKey> {
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        return SecretKey::from_str(&secret).std_context("invalid IROH_SECRET");
    }
    let path = dir.join("secret.key");
    match std::fs::read_to_string(&path) {
        Ok(contents) => SecretKey::from_str(contents.trim())
            .with_std_context(|_| format!("invalid secret key in {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            std::fs::create_dir_all(dir)
                .with_std_context(|_| format!("failed to create {}", dir.display()))?;
            let hex = data_encoding::HEXLOWER.encode(&key.to_bytes());
            std::fs::write(&path, &hex)
                .with_std_context(|_| format!("failed to write {}", path.display()))?;
            info!(path = %path.display(), "generated new secret key");
            Ok(key)
        }
        Err(e) => Err(e).with_std_context(|_| format!("failed to read {}", path.display())),
    }
}

/// Listens on a local TCP port and forwards each socket to the remote endpoint.
async fn run_connect(
    pool: ConnectionPool,
    listener: TcpListener,
    config: ConnectConfig,
    token: CancellationToken,
) -> Result<()> {
    let remote_id = config.remote.0.id;
    let name = Arc::new(config.name);
    loop {
        let (tcp_stream, peer) = select! {
            res = listener.accept() => res.std_context("error accepting tcp connection")?,
            _ = token.cancelled() => break,
        };
        let pool = pool.clone();
        let name = name.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_connect(&pool, remote_id, &name, tcp_stream).await {
                warn!("error forwarding tcp connection from {peer}: {cause}");
            }
        });
    }
    Ok(())
}

/// Forwards a single accepted TCP socket to the remote endpoint.
///
/// The iroh connection comes from the shared pool, so concurrent and successive
/// streams to the same remote reuse one connection. The [`ConnectionRef`] is
/// held until forwarding finishes, which keeps the pool from closing the
/// connection while it is in use.
async fn handle_connect(
    pool: &ConnectionPool,
    remote_id: EndpointId,
    name: &str,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (tcp_recv, tcp_send) = tcp_stream.into_split();
    let connection = get_connection(pool, remote_id).await?;
    let (mut endpoint_send, endpoint_recv) = connection
        .open_bi()
        .await
        .std_context("error opening bidi stream")?;
    write_named_handshake(&mut endpoint_send, name).await?;
    crate::forward_bidi(tcp_recv, tcp_send, endpoint_recv, endpoint_send).await?;
    Ok(())
}

/// Gets a pooled connection to `remote_id`, retrying the connect once on error.
///
/// The pool reuses a live connection if it has one. On a connect failure it
/// retries a single time, which covers a transient discovery or relay hiccup
/// and a connection that was evicted just as it was requested.
async fn get_connection(pool: &ConnectionPool, remote_id: EndpointId) -> Result<ConnectionRef> {
    match pool.get_or_connect(remote_id).await {
        Ok(connection) => Ok(connection),
        Err(cause) => {
            warn!(remote = %remote_id, "connect failed, retrying once: {cause}");
            pool.get_or_connect(remote_id)
                .await
                .with_std_context(|_| format!("error connecting to {remote_id}"))
        }
    }
}

/// Accepts incoming endpoint connections and routes their streams by name.
async fn run_accept(
    endpoint: iroh::Endpoint,
    routes: Arc<HashMap<String, String>>,
    token: CancellationToken,
) {
    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = token.cancelled() => break,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(accepting) = incoming.accept() else {
            continue;
        };
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_connection(accepting, routes).await {
                warn!("error handling incoming connection: {cause}");
            }
        });
    }
}

/// Accepts every bidi stream on one incoming connection and routes each by name.
///
/// A connecting daemon reuses one connection for many TCP streams, so each
/// stream arrives as a separate bidi stream that must be accepted in turn.
async fn handle_connection(
    accepting: iroh::endpoint::Accepting,
    routes: Arc<HashMap<String, String>>,
) -> Result<()> {
    let connection = accepting.await.std_context("error accepting connection")?;
    let remote_id = connection.remote_id();
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            // The remote closing the connection ends the stream loop normally.
            Err(cause) => {
                debug!(%remote_id, "connection closed: {cause}");
                break;
            }
        };
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_stream(send, recv, &routes, remote_id).await {
                warn!(%remote_id, "error handling stream: {cause}");
            }
        });
    }
    Ok(())
}

/// Reads the named handshake from one incoming stream and forwards it.
async fn handle_stream(
    send: noq::SendStream,
    mut recv: noq::RecvStream,
    routes: &HashMap<String, String>,
    remote_id: EndpointId,
) -> Result<()> {
    let name = read_named_handshake(&mut recv).await?;
    let Some(addr) = routes.get(&name) else {
        warn!(%remote_id, %name, "no route for name, dropping stream");
        return Ok(());
    };
    info!(%remote_id, %name, %addr, "forwarding named stream");
    let backend = TcpStream::connect(addr)
        .await
        .with_std_context(|_| format!("error connecting to backend {addr}"))?;
    let (backend_recv, backend_send) = backend.into_split();
    crate::forward_bidi(backend_recv, backend_send, recv, send).await?;
    Ok(())
}

/// Writes the named handshake: prefix, name length (`u32` big-endian), name.
async fn write_named_handshake<W: AsyncWrite + Unpin>(send: &mut W, name: &str) -> Result<()> {
    ensure_any!(
        name.len() <= MAX_NAME_LEN,
        "name too long: {} bytes",
        name.len()
    );
    // The bound above keeps this well within u32 range.
    let len = name.len() as u32;
    send.write_all(&HANDSHAKE_NAMED).await.anyerr()?;
    send.write_all(&len.to_be_bytes()).await.anyerr()?;
    send.write_all(name.as_bytes()).await.anyerr()?;
    Ok(())
}

/// Reads a named handshake written by [`write_named_handshake`].
async fn read_named_handshake<R: AsyncRead + Unpin>(recv: &mut R) -> Result<String> {
    let mut prefix = [0u8; HANDSHAKE_NAMED.len()];
    recv.read_exact(&mut prefix).await.anyerr()?;
    ensure_any!(prefix == HANDSHAKE_NAMED, "invalid named handshake");
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.anyerr()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    ensure_any!(len <= MAX_NAME_LEN, "name too long: {len} bytes");
    let mut name = vec![0u8; len];
    recv.read_exact(&mut name).await.anyerr()?;
    String::from_utf8(name).std_context("name is not valid utf8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_named_handshake_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_named_handshake(&mut a, "boo").await.unwrap();
        let name = read_named_handshake(&mut b).await.unwrap();
        assert_eq!(name, "boo");
    }

    #[tokio::test]
    async fn test_read_named_handshake_rejects_bad_prefix() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"hello").await.unwrap();
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(read_named_handshake(&mut b).await.is_err());
    }

    #[test]
    fn test_parse_config() {
        // A real endpoint id (32-byte ed25519 public key) in hex.
        let id = "0".repeat(64);
        let toml = format!(
            r#"
            [[connect]]
            remote = "{id}"
            name = "boo"
            addr = "localhost:13414"

            [[accept]]
            name = "foo"
            addr = "localhost:31231"

            [[accept]]
            name = "bar"
            addr = "10.0.0.3:80"
            "#
        );
        let config: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.connect.len(), 1);
        assert_eq!(config.connect[0].name, "boo");
        assert_eq!(config.connect[0].addr, "localhost:13414");
        assert_eq!(config.accept.len(), 2);
        assert_eq!(config.accept[1].name, "bar");
    }

    #[test]
    fn test_parse_config_empty() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.connect.is_empty());
        assert!(config.accept.is_empty());
    }

    #[test]
    fn test_static_address_lookup() {
        let id = EndpointId::from_str(&"0".repeat(64)).unwrap();
        let connect = |addr: EndpointAddr| ConnectConfig {
            remote: Remote(addr),
            name: "n".into(),
            addr: "127.0.0.1:1".into(),
        };

        // A bare id carries no hints, so no static lookup is built.
        let bare = connect(EndpointAddr::from(id));
        assert!(static_address_lookup(std::slice::from_ref(&bare)).is_none());

        // A remote with a relay hint produces a static lookup that knows the id.
        let relay = "https://relay.example".parse().unwrap();
        let hinted = connect(EndpointAddr::new(id).with_relay_url(relay));
        let lookup = static_address_lookup(std::slice::from_ref(&hinted)).expect("lookup built");
        assert!(lookup.get_endpoint_info(id).is_some());
    }
}
