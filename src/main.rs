//! Command line arguments.
use clap::{Parser, Subcommand};
use dumbpipe::NodeTicket;
use hex::FromHexError;
use iroh::{endpoint::Connecting, Endpoint, KeyParsingError, NodeAddr, SecretKey};
use n0_snafu::{Result, ResultExt};
use snafu::Snafu;
use std::{
    borrow::Cow,
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    str::FromStr,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    select,
};
use tokio_util::sync::CancellationToken;
use tracing::log::{debug, error};

#[cfg(unix)]
use {
    std::path::{Path, PathBuf},
    tokio::net::{UnixListener, UnixStream},
};

/// Create a dumb pipe between two machines, using an iroh endpoint.
///
/// One side listens, the other side connects. Both sides are identified by a
/// 32 byte node id.
///
/// Connecting to a node id is independent of its IP address. Dumbpipe will try
/// to establish a direct connection even through NATs and firewalls. If that
/// fails, it will fall back to using a relay server.
///
/// For all subcommands, you can specify a secret key using the IROH_SECRET
/// environment variable. If you don't, a random one will be generated.
///
/// You can also specify a port for the endpoint. If you don't, a random one
/// will be chosen.
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on an endpoint and forward stdin/stdout to the first incoming
    /// bidi stream.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    Listen(ListenArgs),

    /// Listen on an endpoint and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a TCP socket for which you have to specify the host and port.
    ListenTcp(ListenTcpArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout.
    ///
    /// A node ticket is required to connect.
    Connect(ConnectArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A node ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the interface and port.
    ConnectTcp(ConnectTcpArgs),

    #[cfg(unix)]
    /// Listen on an endpoint and forward incoming connections to the specified
    /// Unix socket path. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a Unix socket for which you have to specify the path.
    ListenUnix(ListenUnixArgs),

    #[cfg(unix)]
    /// Connect to an endpoint, open a bidi stream, and forward connections
    /// from the specified Unix socket path.
    ///
    /// A node ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a Unix socket for which you have to specify the path.
    ConnectUnix(ConnectUnixArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// A custom ALPN to use for the endpoint.
    ///
    /// This is an expert feature that allows dumbpipe to be used to interact
    /// with existing iroh protocols.
    ///
    /// When using this option, the connect side must also specify the same ALPN.
    /// The listen side will not expect a handshake, and the connect side will
    /// not send one.
    ///
    /// Alpns are byte strings. To specify an utf8 string, prefix it with `utf8:`.
    /// Otherwise, it will be parsed as a hex string.
    #[clap(long)]
    pub custom_alpn: Option<String>,

    /// Use a persistent node key pair
    #[arg(long)]
    persist: bool,
    /// Write and read the node keys at the given location
    #[arg(long)]
    persist_at: Option<PathBuf>,

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl CommonArgs {
    fn alpn(&self) -> Result<Vec<u8>> {
        Ok(match &self.custom_alpn {
            Some(alpn) => parse_alpn(alpn)?,
            None => dumbpipe::ALPN.to_vec(),
        })
    }

    fn is_custom_alpn(&self) -> bool {
        self.custom_alpn.is_some()
    }
}

fn parse_alpn(alpn: &str) -> Result<Vec<u8>> {
    Ok(if let Some(text) = alpn.strip_prefix("utf8:") {
        text.as_bytes().to_vec()
    } else {
        hex::decode(alpn).e()?
    })
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    #[clap(long)]
    pub host: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// The addresses to listen on for incoming tcp connections.
    ///
    /// To listen on all network interfaces, use 0.0.0.0:12345
    #[clap(long)]
    pub addr: String,

    /// The node to connect to
    pub ticket: NodeTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The node to connect to
    pub ticket: NodeTicket,

    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ListenUnixArgs {
    /// Path to the Unix socket to connect to
    #[clap(long)]
    pub socket_path: PathBuf,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ConnectUnixArgs {
    /// Path to the Unix socket to listen on
    #[clap(long)]
    pub socket_path: PathBuf,

    /// The node to connect to
    pub ticket: NodeTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}

/// Copy from a reader to a quinn stream.
///
/// Will send a reset to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_to_quinn(
    mut from: impl AsyncRead + Unpin,
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tracing::trace!("copying to quinn");
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            send.finish()?;
            Ok(size)
        }
        _ = token.cancelled() => {
            // send a reset to the other side immediately
            send.reset(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Copy from a quinn stream to a writer.
///
/// Will send stop to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_from_quinn(
    mut recv: quinn::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => {
            Ok(res?)
        },
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.
fn get_or_create_secret() -> Result<SecretKey> {
    match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret).context("invalid secret"),
        Err(_) => {
            let key = SecretKey::generate(&mut rand::rng());
            eprintln!(
                "using secret key {}",
                data_encoding::HEXLOWER.encode(&key.to_bytes())
            );
            Ok(key)
        }
    }
}

/// Create a new iroh endpoint.
async fn create_endpoint(
    secret_key: SecretKey,
    common: &CommonArgs,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let mut builder = Endpoint::builder().secret_key(secret_key).alpns(alpns);
    if let Some(addr) = common.ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = common.ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    if common.persist || common.persist_at.is_some() {
        builder = builder.secret_key(get_secret_key(common.persist_at.as_ref()).await);
    }
    let endpoint = builder.bind().await?;
    Ok(endpoint)
}

async fn get_secret_key(persist_at: Option<&PathBuf>) -> SecretKey {
    let persist_at_cow = persist_at
        .map(Cow::from) // Reference
        .or_else(|| {
            std::env::home_dir().map(|mut p| {
                p.push(".auth");
                p.push("dumbpipe.key");
                debug!("Persisting key at: {p:?}");
                Cow::from(p) // Owned
            })
        });
    let persist_at = persist_at_cow.as_ref().map(Cow::as_ref);

    match read_key(persist_at).await {
        Ok(Some(result)) => return result,
        Ok(None) => {}
        Err(error) => {
            error!("Error reading persisted dumbpipe key: [{:?}]", error);
        }
    }

    let key = SecretKey::generate(&mut rand::rng());
    if let Some(node_path) = persist_at {
        if let Err(error) = write_key(node_path, &key).await {
            error!("Could not persist dumbpipe key: {node_path:?}: {error:?}");
        }
    }
    key
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PersistError {
    #[snafu(transparent)]
    IOError { source: std::io::Error },

    FileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[snafu(transparent)]
    KeyDecodeError { source: KeyDecodeErrorSource },
}

fn for_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> PersistError {
    return |e| PersistError::FileError { source: e, file };
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyDecodeErrorSource {
    #[snafu(transparent)]
    Hex {
        source: FromHexError,
    },

    #[snafu(transparent)]
    Parsing {
        source: iroh::KeyParsingError,
    },

    InvalidSecretKeySize,
}

impl From<FromHexError> for PersistError {
    fn from(source: FromHexError) -> Self {
        PersistError::KeyDecodeError {
            source: KeyDecodeErrorSource::Hex { source },
        }
    }
}

impl From<KeyParsingError> for PersistError {
    fn from(source: KeyParsingError) -> Self {
        PersistError::KeyDecodeError {
            source: KeyDecodeErrorSource::Parsing { source },
        }
    }
}

async fn read_key(key_path_option: Option<&Path>) -> Result<Option<SecretKey>, PersistError> {
    if let Some(key_path) = key_path_option {
        if !key_path.exists() {
            debug!("Secret key not found: {:?}", &key_path);
            return Ok(None);
        }
        let key_base64 = tokio::fs::read_to_string(key_path).await?;
        let key_base64 = key_base64.trim();
        let key_bytes = hex::decode(key_base64)?;
        if key_bytes.len() != 32 {
            return Err(PersistError::KeyDecodeError {
                source: KeyDecodeErrorSource::InvalidSecretKeySize,
            });
        }
        let key = SecretKey::try_from(&key_bytes[0..32]).map_err(KeyParsingError::from)?;
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

async fn write_key(key_path: &Path, key: &SecretKey) -> Result<(), PersistError> {
    let mut secret_hex = hex::encode(key.to_bytes());
    secret_hex.push('\n');
    let mut open_options = tokio::fs::OpenOptions::new();
    open_options.mode(0o400); // Read for owner only
    create_file(open_options, key_path, &secret_hex).await?;
    Ok(())
}

async fn create_file(
    mut open_options: tokio::fs::OpenOptions,
    file: &Path,
    content: &str,
) -> Result<(), PersistError> {
    let mut parent = file.to_owned();
    if parent.pop() {
        fs::create_dir_all(parent.clone())
            .await
            .map_err(for_file(parent))?
    }
    let mut open_file = open_options.create(true).write(true).open(file).await?;
    open_file
        .write_all(content.as_bytes())
        .await
        .map_err(for_file(file.to_path_buf()))?;
    Ok(())
}

fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair, aborting both sides when either one forwarder is done,
/// or when control-c is pressed.
async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
) -> Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let forward_from_stdin = tokio::spawn(async move {
        copy_to_quinn(from1, to2, token1.clone())
            .await
            .map_err(cancel_token(token1))
    });
    let forward_to_stdout = tokio::spawn(async move {
        copy_from_quinn(from2, to1, token2.clone())
            .await
            .map_err(cancel_token(token2))
    });
    let _control_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });
    forward_to_stdout.await.e()?.e()?;
    forward_from_stdin.await.e()?.e()?;
    Ok(())
}

async fn listen_stdio(args: ListenArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its home relay and addresses before making a ticket
    endpoint.online().await;
    let node = endpoint.node_addr();
    let mut short = node.clone();
    let ticket = NodeTicket::new(node);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Listening. To connect, use:\ndumbpipe connect {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect {short}");
    }

    loop {
        let Some(connecting) = endpoint.accept().await else {
            break;
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_node_id = &connection.remote_node_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = match connection.accept_bi().await {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting stream: {}", cause);
                // if accept_bi fails, we want to continue accepting connections
                continue;
            }
        };
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if !args.common.is_custom_alpn() {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.e()?;
            snafu::ensure_whatever!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        if args.recv_only {
            tracing::info!("forwarding stdout to {} (ignoring stdin)", remote_node_id);
            forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await?;
        } else {
            tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
            forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
        }
        // stop accepting connections after the first successful one
        break;
    }
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![]).await?;
    let addr = args.ticket.node_addr();
    let remote_node_id = addr.node_id;
    // connect to the node, try only once
    let connection = endpoint.connect(addr.clone(), &args.common.alpn()?).await?;
    tracing::info!("connected to {}", remote_node_id);
    // open a bidi stream, try only once
    let (mut s, r) = connection.open_bi().await.e()?;
    tracing::info!("opened bidi stream to {}", remote_node_id);
    // send the handshake unless we are using a custom alpn
    // when using a custom alpn, evertyhing is up to the user
    if !args.common.is_custom_alpn() {
        // the connecting side must write first. we don't know if there will be something
        // on stdin, so just write a handshake.
        s.write_all(&dumbpipe::HANDSHAKE).await.e()?;
    }
    if args.recv_only {
        tracing::info!("forwarding stdout to {} (ignoring stdin)", remote_node_id);
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await?;
    } else {
        tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    }
    tokio::io::stdout().flush().await.e()?;
    Ok(())
}

/// Listen on a tcp port and forward incoming connections to an endpoint.
async fn connect_tcp(args: ConnectTcpArgs) -> Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .context("unable to bind endpoint")?;
    tracing::info!("tcp listening on {:?}", addrs);

    // Wait for our own endpoint to be ready before trying to connect.
    endpoint.online().await;

    let tcp_listener = match tokio::net::TcpListener::bind(addrs.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", addrs, cause);
            return Ok(());
        }
    };
    async fn handle_tcp_accept(
        next: io::Result<(tokio::net::TcpStream, SocketAddr)>,
        addr: NodeAddr,
        endpoint: Endpoint,
        handshake: bool,
        alpn: &[u8],
    ) -> Result<()> {
        let (tcp_stream, tcp_addr) = next.context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let remote_node_id = addr.node_id;
        let connection = endpoint
            .connect(addr, alpn)
            .await
            .context(format!("error connecting to {remote_node_id}"))?;
        let (mut endpoint_send, endpoint_recv) = connection
            .open_bi()
            .await
            .context(format!("error opening bidi stream to {remote_node_id}"))?;
        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, evertyhing is up to the user
        if handshake {
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            endpoint_send.write_all(&dumbpipe::HANDSHAKE).await.e()?;
        }
        forward_bidi(tcp_recv, tcp_send, endpoint_recv, endpoint_send).await?;
        Ok::<_, n0_snafu::Error>(())
    }
    let addr = args.ticket.node_addr();
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let endpoint = endpoint.clone();
        let addr = addr.clone();
        let handshake = !args.common.is_custom_alpn();
        let alpn = args.common.alpn()?;
        tokio::spawn(async move {
            if let Err(cause) = handle_tcp_accept(next, addr, endpoint, handshake, &alpn).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Listen on an endpoint and forward incoming connections to a tcp socket.
async fn listen_tcp(args: ListenTcpArgs) -> Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => snafu::whatever!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.online().await;
    let node_addr = endpoint.node_addr();
    let mut short = node_addr.clone();
    let ticket = NodeTicket::new(node_addr);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Forwarding incoming requests to '{}'.", args.host);
    eprintln!("To connect, use e.g.:");
    eprintln!("dumbpipe connect-tcp {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect-tcp {short}");
    }
    tracing::info!("node id is {}", ticket.node_addr().node_id);
    tracing::info!("derp url is {:?}", ticket.node_addr().relay_url);

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        connecting: Connecting,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
    ) -> Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_node_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.e()?;
            snafu::ensure_whatever!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        let connection = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .context(format!("error connecting to {addrs:?}"))?;
        let (read, write) = connection.into_split();
        forward_bidi(read, write, r, s).await?;
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let addrs = addrs.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(connecting, addrs, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
/// Listen on an endpoint and forward incoming connections to a Unix socket.
async fn listen_unix(args: ListenUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.online().await;
    let node_addr = endpoint.node_addr();
    let mut short = node_addr.clone();
    let ticket = NodeTicket::new(node_addr);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!(
        "Forwarding incoming requests to '{}'.",
        socket_path.display()
    );
    eprintln!("To connect, use e.g.:");
    eprintln!("dumbpipe connect-unix --socket-path /path/to/client.sock {ticket}");
    eprintln!("dumbpipe connect-tcp --addr 127.0.0.1:8080 {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect-unix --socket-path /path/to/client.sock {short}");
        eprintln!("dumbpipe connect-tcp --addr 127.0.0.1:8080 {short}");
    }
    tracing::info!("node id is {}", ticket.node_addr().node_id);
    tracing::info!("derp url is {:?}", ticket.node_addr().relay_url);

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        connecting: Connecting,
        socket_path: PathBuf,
        handshake: bool,
    ) -> Result<()> {
        tracing::trace!("accepting connection");
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_node_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            tracing::trace!("reading handshake");
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.e()?;
            snafu::ensure_whatever!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
            tracing::trace!("handshake verified");
        }
        tracing::trace!("connecting to backend socket {:?}", socket_path);
        let connection = UnixStream::connect(&socket_path)
            .await
            .context(format!("error connecting to {socket_path:?}"))?;
        tracing::trace!("connected to backend socket");
        let (read, write) = connection.into_split();
        tracing::trace!("starting forward_bidi");
        forward_bidi(read, write, r, s).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let socket_path = socket_path.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(connecting, socket_path, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
/// A RAII guard to clean up a Unix socket file.
struct UnixSocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("failed to remove socket file {:?}: {}", self.path, e);
            }
        }
    }
}

#[cfg(unix)]
/// Listen on a Unix socket and forward connections to an endpoint.
async fn connect_unix(args: ConnectUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .context("unable to bind endpoint")?;
    tracing::info!("unix listening on {:?}", socket_path);

    // Wait for our own endpoint to be ready before trying to connect.
    endpoint.online().await;

    // Remove existing socket file if it exists
    if let Err(e) = tokio::fs::remove_file(&socket_path).await {
        if e.kind() != io::ErrorKind::NotFound {
            snafu::whatever!("failed to remove existing socket file: {}", e);
        }
    }

    let addr = args.ticket.node_addr();
    tracing::info!("connecting to remote node: {:?}", addr);
    let connection = endpoint
        .connect(addr.clone(), &args.common.alpn()?)
        .await
        .context("failed to connect to remote node")?;
    tracing::info!("connected to remote node successfully");

    let unix_listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind Unix socket at {socket_path:?}"))?;
    tracing::info!("bound local unix socket: {:?}", socket_path);

    let _guard = UnixSocketGuard {
        path: socket_path.clone(),
    };

    async fn handle_unix_accept(
        next: io::Result<(UnixStream, tokio::net::unix::SocketAddr)>,
        connection: iroh::endpoint::Connection,
        handshake: bool,
    ) -> Result<()> {
        tracing::trace!("handling new local connection");
        let (unix_stream, unix_addr) = next.context("error accepting unix connection")?;
        let (unix_recv, unix_send) = unix_stream.into_split();
        tracing::trace!("got unix connection from {:?}", unix_addr);

        tracing::trace!("opening bidi stream");
        let (mut endpoint_send, endpoint_recv) = connection
            .open_bi()
            .await
            .context("error opening bidi stream")?;
        tracing::trace!("bidi stream opened");

        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, everything is up to the user
        if handshake {
            tracing::trace!("sending handshake");
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            endpoint_send.write_all(&dumbpipe::HANDSHAKE).await.e()?;
            tracing::trace!("handshake sent");
        }

        tracing::trace!("starting forward_bidi");
        forward_bidi(unix_recv, unix_send, endpoint_recv, endpoint_send).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    tracing::info!("entering accept loop");
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = unix_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        tracing::trace!("accepted a local connection");
        let connection = connection.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            tracing::trace!("spawning handler task");
            if let Err(cause) = handle_unix_accept(next, connection, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
            tracing::trace!("handler task finished");
        });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let res = match args.command {
        Commands::Listen(args) => listen_stdio(args).await,
        Commands::ListenTcp(args) => listen_tcp(args).await,
        Commands::Connect(args) => connect_stdio(args).await,
        Commands::ConnectTcp(args) => connect_tcp(args).await,

        #[cfg(unix)]
        Commands::ListenUnix(args) => listen_unix(args).await,

        #[cfg(unix)]
        Commands::ConnectUnix(args) => connect_unix(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}
