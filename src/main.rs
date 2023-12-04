//! Command line arguments.
use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh_net::{
    key::SecretKey,
    magic_endpoint::{get_alpn, get_remote_node_id},
    MagicEndpoint, NodeAddr,
};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, io, net::ToSocketAddrs, str::FromStr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

/// The ALPN protocol for dumbpipe.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send a fixed size handshake to make sure the stream is created.
const ALPN: &[u8] = b"DUMBPIPEV0";
/// The handshake to send when connecting.
///
/// The side that calls open_bi() first must send this handshake, the side that
/// calls accept_bi() must consume it.
const HANDSHAKE: [u8; 5] = *b"hello";

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on a magicsocket and forward stdin/stdout to the first incoming
    /// bidi stream.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    Listen(ListenArgs),

    /// Listen on a magicsocket and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    ///
    /// As far as the magic socket is concerned, this is listening. But it is
    /// connecting to a TCP socket for which you have to specify the host and port.
    ListenTcp(ListenTcpArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A node ticket is required to connect.
    ///
    /// As far as the magic socket is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the port.
    ConnectTcp(ConnectTcpArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout.
    ///
    /// A node ticket is required to connect.
    Connect(ConnectArgs),
}

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
///
/// TODO: find a way to move this to iroh-net.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTicket {
    /// The address of the node.
    addr: NodeAddr,
}

impl NodeTicket {
    /// Serialize to postcard bytes.
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard::to_stdvec is infallible")
    }

    /// Deserialize from postcard bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let ticket: Self = postcard::from_bytes(bytes)?;
        ticket.verify().context("invalid ticket")?;
        Ok(ticket)
    }

    /// Verify this ticket.
    fn verify(&self) -> anyhow::Result<()> {
        // do we need this? a ticket with just a node id still might be useful
        // given some sort of discovery mechanism.
        anyhow::ensure!(!self.addr.info.is_empty(), "no node info");
        Ok(())
    }

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = "node".to_string();
        data_encoding::BASE32_NOPAD.encode_append(&self.to_bytes(), &mut out);
        out.make_ascii_lowercase();
        out
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> anyhow::Result<Self> {
        let Some(base32) = str.strip_prefix("node") else {
            anyhow::bail!("invalid prefix");
        };
        let bytes = data_encoding::BASE32_NOPAD
            .decode(base32.to_ascii_uppercase().as_bytes())
            .context("invalid base32")?;
        Self::from_bytes(&bytes)
    }
}

impl Display for NodeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

impl FromStr for NodeTicket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::deserialize(s)
    }
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
    /// The port to listen on.
    #[clap(long, default_value_t = 0)]
    pub magic_port: u16,

    /// The secret key to use. Random by default.
    #[clap(long)]
    pub secret: Option<iroh_net::key::SecretKey>,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    #[clap(long)]
    pub host: String,

    /// The port to use for the magicsocket. Random by default.
    #[clap(long, default_value_t = 0)]
    pub magic_port: u16,

    /// The secret key to use. Random by default.
    #[clap(long)]
    pub secret: Option<iroh_net::key::SecretKey>,
}

#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// The interfaces to listen on for incoming tcp connections.
    #[clap(long)]
    pub host: String,

    /// The port to use for the magicsocket. Random by default.
    #[clap(long, default_value_t = 0)]
    pub magic_port: u16,

    /// The node to connect to
    pub ticket: NodeTicket,

    /// The secret key to use. Random by default.
    #[clap(long)]
    pub secret: Option<iroh_net::key::SecretKey>,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The node to connect to
    pub ticket: NodeTicket,

    /// The port to bind to.
    #[clap(long, default_value_t = 0)]
    pub port: u16,

    /// The secret key to use. Random by default.
    #[clap(long)]
    pub secret: Option<iroh_net::key::SecretKey>,
}

/// Copy from a reader to a quinn stream, calling finish() on the stream when
/// the reader is done or the operation is cancelled.
async fn copy_to_quinn(
    mut from: impl AsyncRead + Unpin,
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> anyhow::Result<()> {
    tokio::select! {
        _ = tokio::io::copy(&mut from, &mut send) => {}
        _ = token.cancelled() => {}
    }
    send.finish().await?;
    Ok(())
}

/// Copy from a quinn stream to a writer, calling stop() on the stream when
/// the writer is done or the operation is cancelled.
async fn copy_from_quinn(
    mut recv: quinn::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> anyhow::Result<()> {
    tokio::select! {
        _ = tokio::io::copy(&mut recv, &mut to) => {}
        _ = token.cancelled() => {
            recv.stop(0u8.into())?;
        }
    }
    Ok(())
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.
fn get_or_create_secret(secret: Option<SecretKey>) -> SecretKey {
    secret.unwrap_or_else(|| {
        let key = SecretKey::generate();
        eprintln!("using secret key {}", key);
        key
    })
}

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair, aborting both sides when either one forwarder is done,
/// or when control-c is pressed.
async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
) -> anyhow::Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let forward_from_stdin = tokio::spawn(async move {
        copy_to_quinn(from1, to2, token1.clone()).await.ok();
        token1.cancel();
    });
    let forward_to_stdout = tokio::spawn(async move {
        copy_from_quinn(from2, to1, token2.clone()).await.ok();
        token2.cancel();
    });
    let _control_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });
    forward_to_stdout.await?;
    forward_from_stdin.await?;
    Ok(())
}

async fn listen_stdio(args: ListenArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret(args.secret);
    let endpoint = MagicEndpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind(args.magic_port)
        .await?;
    // wait for the endpoint to figure out its address before making a ticket
    while endpoint.my_derp().is_none() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let addr = endpoint.my_addr().await?;
    let ticket = NodeTicket { addr };
    eprintln!(
        "Listening. To connect, use:\ndumbpipe connect {}",
        ticket.serialize()
    );

    while let Some(connecting) = endpoint.accept().await {
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_node_id = get_remote_node_id(&connection)?;
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
        // read the handshake and verify it
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).await?;
        anyhow::ensure!(buf == HANDSHAKE, "invalid handshake");
        tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
        // stop accepting connections after the first successful one
        break;
    }
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret(args.secret);
    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind(args.port)
        .await?;
    let addr = args.ticket.addr;
    let remote_node_id = addr.node_id;
    // connect to the node, try only once
    let connection = endpoint.connect(addr, ALPN).await?;
    tracing::info!("connected to {}", remote_node_id);
    // open a bidi stream, try only once
    let (mut s, r) = connection.open_bi().await?;
    tracing::info!("opened bidi stream to {}", remote_node_id);
    // the connecting side must write first. we don't know if there will be something
    // on stdin, so just write a handshake.
    s.write_all(&HANDSHAKE).await?;
    tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
    forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    Ok(())
}

/// Listen on a tcp port and forward incoming connections to a magicsocket.
async fn connect_tcp(args: ConnectTcpArgs) -> anyhow::Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret(args.secret);
    let endpoint = MagicEndpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind(args.magic_port)
        .await?;
    tracing::info!("tcp listening on {:?}", addrs);
    let tcp_listener = match tokio::net::TcpListener::bind(addrs.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", addrs, cause);
            return Ok(());
        }
    };
    let addr = args.ticket.addr;
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let (tcp_stream, tcp_addr) = match next {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting tcp connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let endpoint = endpoint.clone();
        let addr = addr.clone();
        tokio::spawn(async move {
            let (tcp_recv, tcp_send) = tcp_stream.into_split();
            tracing::info!("got tcp connection from {}", tcp_addr);
            let remote_node_id = addr.node_id;
            let connection = endpoint.connect(addr, ALPN).await.map_err(|e| {
                tracing::error!("error connecting to {}: {}", remote_node_id, e);
                e
            })?;
            let (mut magic_send, magic_recv) = connection.open_bi().await.map_err(|e| {
                tracing::error!("error opening bidi stream to {}: {}", remote_node_id, e);
                e
            })?;
            magic_send.write_all(&HANDSHAKE).await?;
            forward_bidi(tcp_recv, tcp_send, magic_recv, magic_send).await?;
            anyhow::Ok(())
        });
    }
    Ok(())
}

/// Listen on a magicsocket and forward incoming connections to a tcp socket.
async fn listen_tcp(args: ListenTcpArgs) -> anyhow::Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret(args.secret);
    let endpoint = MagicEndpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind(args.magic_port)
        .await?;
    // wait for the endpoint to figure out its address before making a ticket
    while endpoint.my_derp().is_none() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let addr = endpoint.my_addr().await?;
    let ticket = NodeTicket { addr };
    eprintln!(
        "Forwarding incoming requests to '{}'. Use node ticket '{}' to connect",
        args.host, ticket,
    );

    while let Some(connecting) = endpoint.accept().await {
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_node_id = get_remote_node_id(&connection)?;
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
        // read the handshake and verify it
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).await?;
        anyhow::ensure!(buf == HANDSHAKE, "invalid handshake");
        let addrs = addrs.clone();
        tokio::spawn(async move {
            let connection = match tokio::net::TcpStream::connect(addrs.as_slice()).await {
                Ok(connection) => connection,
                Err(cause) => {
                    tracing::error!("error connecting to {:?}: {}", addrs, cause);
                    return Ok(());
                }
            };
            let (read, write) = connection.into_split();
            forward_bidi(read, write, r, s).await?;
            anyhow::Ok(())
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let res = match args.command {
        Commands::Listen(args) => listen_stdio(args).await,
        Commands::ListenTcp(args) => listen_tcp(args).await,
        Commands::Connect(args) => connect_stdio(args).await,
        Commands::ConnectTcp(args) => connect_tcp(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1)
        }
    }
}
