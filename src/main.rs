//! Command line arguments.
use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh_net::{MagicEndpoint, NodeAddr};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, io, str::FromStr};
use tokio_util::sync::CancellationToken;

const ALPN: &[u8] = b"DUMBPIPEV0";

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Listen(ListenArgs),
    Connect(ConnectArgs),
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
    pub port: u16,

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

async fn forward_from_stdin(
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    tokio::select! {
        _ = tokio::io::copy(&mut stdin, &mut send) => {}
        _ = token.cancelled() => {}
    }
    send.finish().await?;
    Ok(())
}

async fn forward_to_stdout(
    mut recv: quinn::RecvStream,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let mut stdout = tokio::io::stdout();
    tokio::select! {
        _ = tokio::io::copy(&mut recv, &mut stdout) => {}
        _ = token.cancelled() => {
            recv.stop(0u8.into())?;
        }
    }
    Ok(())
}

async fn forward_stdio(send: quinn::SendStream, recv: quinn::RecvStream) -> anyhow::Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let forward_from_stdin = tokio::spawn(async move {
        forward_from_stdin(send, token1.clone()).await.ok();
        token1.cancel();
    });
    let forward_to_stdout = tokio::spawn(async move {
        forward_to_stdout(recv, token2.clone()).await.ok();
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
        .bind(args.port)
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
        forward_stdio(s, r).await?;
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
    forward_stdio(s, r).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let res = match args.command {
        Commands::Listen(args) => listen(args).await,
        Commands::Connect(args) => connect(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1)
        }
    }
}
