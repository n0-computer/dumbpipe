//! Command line arguments.
use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh_net::{MagicEndpoint, NodeAddr};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, io, str::FromStr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

const ALPN: &[u8] = b"DUMBPIPEV0";

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on a magicsocket and forward stdin/stdout to the first incoming
    /// bidi stream.
    Listen(ListenArgs),
    /// Listen on a magicsocket and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ForwardTcp(ForwardTcpArgs),
    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout
    /// to it.
    Connect(ConnectArgs),
    /// Listen on a magicsocket and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ListenTcp(ListenTcpArgs),
}

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTicket {
    /// The provider to get a file from.
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
pub struct ForwardTcpArgs {
    #[clap(long)]
    pub host: Option<String>,

    /// The port to forward to.
    #[clap(long, default_value_t = 0)]
    pub port: u16,

    /// The secret key to use. Random by default.
    #[clap(long)]
    pub secret: Option<iroh_net::key::SecretKey>,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    /// The port to listen on for incoming tcp connections.
    #[clap(long)]
    pub port: u16,

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

async fn forward_from(
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

async fn forward_to(
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
        forward_from(from1, to2, token1.clone()).await.ok();
        token1.cancel();
    });
    let forward_to_stdout = tokio::spawn(async move {
        forward_to(from2, to1, token2.clone()).await.ok();
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

async fn listen(args: ListenArgs) -> anyhow::Result<()> {
    let secret_key = args.secret.unwrap_or_else(|| {
        let res = iroh_net::key::SecretKey::generate();
        eprintln!("using secret key {}", res);
        res
    });
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
        let Ok(connection) = connecting.await else {
            // if accept fails, we want to continue accepting connections
            continue;
        };
        let Ok((s, mut r)) = connection.accept_bi().await else {
            // if accept_bi fails, we want to continue accepting connections
            continue;
        };
        // read the handshake and verify it
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).await?;
        anyhow::ensure!(&buf == b"hello", "invalid hello");
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
        break;
    }
    Ok(())
}

async fn connect(args: ConnectArgs) -> anyhow::Result<()> {
    let secret_key = args
        .secret
        .unwrap_or_else(iroh_net::key::SecretKey::generate);
    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind(args.port)
        .await?;
    let addr = args.ticket.addr;
    let connection = endpoint.connect(addr, ALPN).await?;
    let (mut s, r) = connection.open_bi().await?;
    // the connecting side must write first. we don't know if there will be something
    // on stdin, so just write a handshake.
    s.write_all(b"hello").await?;
    forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    Ok(())
}

async fn listen_tcp(args: ListenTcpArgs) -> anyhow::Result<()> {
    let secret_key = args.secret.unwrap_or_else(|| {
        let res = iroh_net::key::SecretKey::generate();
        eprintln!("using secret key {}", res);
        res
    });
    let endpoint = MagicEndpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind(args.magic_port)
        .await?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", args.port)).await?;
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            continue;
        };
        eprintln!("got connection from {}", addr);
        let connection = endpoint.connect(args.ticket.addr.clone(), ALPN).await?;
        let (mut s, r) = connection.open_bi().await?;
    }
    Ok(())
}

async fn forward_tcp(args: ForwardTcpArgs) -> anyhow::Result<()> {
    let secret_key = args.secret.unwrap_or_else(|| {
        let res = iroh_net::key::SecretKey::generate();
        eprintln!("using secret key {}", res);
        res
    });
    let endpoint = MagicEndpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind(args.port)
        .await?;
    // wait for the endpoint to figure out its address before making a ticket
    while endpoint.my_derp().is_none() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let addr = endpoint.my_addr().await?;
    let ticket = NodeTicket { addr };
    eprintln!(
        "Forwarding incoming requests to port {}. Use e.g. http://{}.localhost:8100 to connect.",
        args.port, ticket.addr.node_id,
    );

    while let Some(connecting) = endpoint.accept().await {
        let Ok(connection) = connecting.await else {
            // if accept fails, we want to continue accepting connections
            continue;
        };
        let Ok((s, mut r)) = connection.accept_bi().await else {
            // if accept_bi fails, we want to continue accepting connections
            continue;
        };
        println!("got connection");
        // read the handshake and verify it
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).await?;
        anyhow::ensure!(&buf == b"hello", "invalid hello");
        let host = args.host.clone().unwrap_or_else(|| "localhost".to_string());
        println!("got handshake");
        let port = args.port;
        tokio::spawn(async move {
            let connection = tokio::net::TcpStream::connect((host, port)).await?;
            let (read, write) = connection.into_split();
            forward_bidi(read, write, r, s).await?;
            anyhow::Ok(())
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let res = match args.command {
        Commands::Listen(args) => listen(args).await,
        Commands::Connect(args) => connect(args).await,
        Commands::ForwardTcp(args) => forward_tcp(args).await,
        Commands::ListenTcp(args) => listen_tcp(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1)
        }
    }
}
