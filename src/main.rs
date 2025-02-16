//! Command line arguments.
use anyhow::Context;
use clap::{Parser, Subcommand};
use dumbpipe::NodeTicket;
use iroh::{
    endpoint::{get_remote_node_id, Connecting},
    Endpoint, NodeAddr, SecretKey,
};
use quinn::Connection;
use std::{
    collections::HashMap, io, net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs}, str::FromStr, sync::Arc
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt}, net::UdpSocket, select
};
use tokio_util::sync::CancellationToken;
mod udpconn;

/// Create a dumb pipe between two machines, using an iroh magicsocket.
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
/// You can also specify a port for the magicsocket. If you don't, a random one
/// will be chosen.
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

    /// Listen on a magicsocket and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    /// 
    /// Will print a node ticket on stderr that can be used to connect.
    /// 
    /// As far as the magic socket is concerned, this is listening. But it is
    /// connecting to a UDP socket for which you have to specify the host and port.
    ListenUdp(ListenUdpArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout.
    ///
    /// A node ticket is required to connect.
    Connect(ConnectArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A node ticket is required to connect.
    ///
    /// As far as the magic socket is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the interface and port.
    ConnectTcp(ConnectTcpArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout
    /// to it.
    /// 
    /// A node ticket is required to connect.
    /// 
    /// As far as the magic socket is concerned, this is connecting. But it is
    /// listening on a UDP socket for which you have to specify the interface and port.
    ConnectUdp(ConnectUdpArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The IPv4 address that magicsocket will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub magic_ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that magicsocket will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub magic_ipv6_addr: Option<SocketAddrV6>,

    /// A custom ALPN to use for the magicsocket.
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

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl CommonArgs {
    fn alpn(&self) -> anyhow::Result<Vec<u8>> {
        Ok(match &self.custom_alpn {
            Some(alpn) => parse_alpn(alpn)?,
            None => dumbpipe::ALPN.to_vec(),
        })
    }

    fn is_custom_alpn(&self) -> bool {
        self.custom_alpn.is_some()
    }
}

fn parse_alpn(alpn: &str) -> anyhow::Result<Vec<u8>> {
    Ok(if let Some(text) = alpn.strip_prefix("utf8:") {
        text.as_bytes().to_vec()
    } else {
        hex::decode(alpn)?
    })
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
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
pub struct ListenUdpArgs {
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
pub struct ConnectUdpArgs {
    /// The addresses to listen on for incoming udp connections.
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
            Err(io::Error::new(io::ErrorKind::Other, "cancelled"))
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
            Err(io::Error::new(io::ErrorKind::Other, "cancelled"))
        }
    }
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.
fn get_or_create_secret() -> anyhow::Result<SecretKey> {
    match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret).context("invalid secret"),
        Err(_) => {
            let key = SecretKey::generate(rand::rngs::OsRng);
            eprintln!("using secret key {}", key);
            Ok(key)
        }
    }
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
) -> anyhow::Result<()> {
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
    forward_to_stdout.await??;
    forward_from_stdin.await??;
    Ok(())
}

async fn listen_stdio(args: ListenArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder()
        .alpns(vec![args.common.alpn()?])
        .secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.home_relay().initialized().await?;
    let node = endpoint.node_addr().await?;
    let mut short = node.clone();
    let ticket = NodeTicket::new(node);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Listening. To connect, use:\ndumbpipe connect {}", ticket);
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect {}", short);
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
        if !args.common.is_custom_alpn() {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
        // stop accepting connections after the first successful one
        break;
    }
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder().secret_key(secret_key).alpns(vec![]);

    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    let addr = args.ticket.node_addr();
    let remote_node_id = addr.node_id;
    // connect to the node, try only once
    let connection = endpoint.connect(addr.clone(), &args.common.alpn()?).await?;
    tracing::info!("connected to {}", remote_node_id);
    // open a bidi stream, try only once
    let (mut s, r) = connection.open_bi().await?;
    tracing::info!("opened bidi stream to {}", remote_node_id);
    // send the handshake unless we are using a custom alpn
    // when using a custom alpn, evertyhing is up to the user
    if !args.common.is_custom_alpn() {
        // the connecting side must write first. we don't know if there will be something
        // on stdin, so just write a handshake.
        s.write_all(&dumbpipe::HANDSHAKE).await?;
    }
    tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
    forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    tokio::io::stdout().flush().await?;
    Ok(())
}

/// Listen on a tcp port and forward incoming connections to a magicsocket.
async fn connect_tcp(args: ConnectTcpArgs) -> anyhow::Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder().alpns(vec![]).secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await.context("unable to bind magicsock")?;
    tracing::info!("tcp listening on {:?}", addrs);
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
    ) -> anyhow::Result<()> {
        let (tcp_stream, tcp_addr) = next.context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let remote_node_id = addr.node_id;
        let connection = endpoint
            .connect(addr, alpn)
            .await
            .context(format!("error connecting to {}", remote_node_id))?;
        let (mut magic_send, magic_recv) = connection
            .open_bi()
            .await
            .context(format!("error opening bidi stream to {}", remote_node_id))?;
        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, evertyhing is up to the user
        if handshake {
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            magic_send.write_all(&dumbpipe::HANDSHAKE).await?;
        }
        forward_bidi(tcp_recv, tcp_send, magic_recv, magic_send).await?;
        anyhow::Ok(())
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

pub struct SplitUdpConn {
    // TODO: Do we need to store this connection?
    // Holding on to this for the future where we need to cleanup the resources.
    connection: quinn::Connection,
    send: quinn::SendStream,
}

impl SplitUdpConn {
    pub fn new(connection: quinn::Connection, send: quinn::SendStream) -> Self {
        Self {
            connection,
            send
        }
    }
}

// 1- Receives request message from socket
// 2- Forwards it to the quinn stream
// 3- Receives response message back from quinn stream
// 4- Forwards it back to the socket
async fn connect_udp(args: ConnectUdpArgs) -> anyhow::Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder().secret_key(secret_key).alpns(vec![]);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await.context("unable to bind magicsock")?;
    tracing::info!("udp listening on {:?}", addrs);
    let socket = Arc::new(UdpSocket::bind(addrs.as_slice()).await?);

    let node_addr = args.ticket.node_addr();
    let mut buf: Vec<u8> = vec![0u8; 65535];
    let mut conns = HashMap::<SocketAddr, SplitUdpConn>::new();
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, sock_addr)) => {
                // Check if we already have a connection for this socket address
                let connection = match conns.get_mut(&sock_addr) {
                    Some(conn) => conn,
                    None => {
                        // We need to finish the connection to be done or we should use something like promise because
                        // when the connection was getting established, it might receive another message.
                        let endpoint = endpoint.clone();
                        let addr = node_addr.clone();
                        let handshake = !args.common.is_custom_alpn();
                        let alpn = args.common.alpn()?;
                        
                        let remote_node_id = addr.node_id;
                        tracing::info!("forwarding UDP to {}", remote_node_id);

                        // connect to the node, try only once
                        let connection = endpoint
                            .connect(addr.clone(), &alpn)
                            .await
                            .context(format!("error connecting to {}", remote_node_id))?;
                        tracing::info!("connected to {}", remote_node_id);

                        // open a bidi stream, try only once
                        let (mut send, recv) = connection
                            .open_bi()
                            .await
                            .context(format!("error opening bidi stream to {}", remote_node_id))?;
                        tracing::info!("opened bidi stream to {}", remote_node_id);

                        // send the handshake unless we are using a custom alpn
                        if handshake {
                            send.write_all(&dumbpipe::HANDSHAKE).await?;
                        }

                        let sock_send = socket.clone();
                        // Spawn a task for listening the quinn connection, and forwarding the data to the UDP socket
                        tokio::spawn(async move {
                            // 3- Receives response message back from quinn stream
                            // 4- Forwards it back to the socket
                            if let Err(cause) = udpconn::handle_udp_accept(sock_addr, sock_send, recv )
                            .await {
                                // log error at warn level
                                //
                                // we should know about it, but it's not fatal
                                tracing::warn!("error handling connection: {}", cause);

                                // TODO: cleanup resources
                            }
                        });

                        // Create and store the split connection
                        let split_conn = SplitUdpConn::new(connection.clone(), send);
                        conns.insert(sock_addr, split_conn);
                        conns.get_mut(&sock_addr).expect("connection was just inserted")
                    }
                };
                
                tracing::info!("forward_udp_to_quinn: Received {} bytes from {}", size, sock_addr);

                // 1- Receives request message from socket
                // 2- Forwards it to the quinn stream
                if let Err(e) = connection.send.write_all(&buf[..size]).await {
                    tracing::error!("Error writing to Quinn stream: {}", e);
                    // TODO: Cleanup the resources on error.
                    // Remove the failed connection
                    // conns.remove(&sock_addr);
                    return Err(e.into());
                }
            }
            Err(e) => {
                tracing::warn!("error receiving from UDP socket: {}", e);
                break;
            }
        }
    }
    Ok(())
}

/// Listen on a magicsocket and forward incoming connections to a tcp socket.
async fn listen_tcp(args: ListenTcpArgs) -> anyhow::Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder()
        .alpns(vec![args.common.alpn()?])
        .secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.home_relay().initialized().await?;
    let node_addr = endpoint.node_addr().await?;
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
        eprintln!("or:\ndumbpipe connect-tcp {}", short);
    }
    tracing::info!("node id is {}", ticket.node_addr().node_id);
    tracing::info!("derp url is {:?}", ticket.node_addr().relay_url);

    // handle a new incoming connection on the magic endpoint
    async fn handle_magic_accept(
        connecting: Connecting,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
    ) -> anyhow::Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = get_remote_node_id(&connection)?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        let connection = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .context(format!("error connecting to {:?}", addrs))?;
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
            if let Err(cause) = handle_magic_accept(connecting, addrs, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Listen on a magicsocket and forward incoming connections to a udp socket.
async fn listen_udp(args: ListenUdpArgs) -> anyhow::Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder()
        .alpns(vec![args.common.alpn()?])
        .secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.home_relay().initialized().await?;
    let node_addr = endpoint.node_addr().await?;
    let mut short = node_addr.clone();
    let ticket = NodeTicket::new(node_addr);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Forwarding incoming requests to '{}'.", args.host);
    eprintln!("To connect, use e.g.:");
    eprintln!("dumbpipe connect-udp {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect-udp {}", short);
    }
    tracing::info!("node id is {}", ticket.node_addr().node_id);
    tracing::info!("derp url is {:?}", ticket.node_addr().relay_url);

    // handle a new incoming connection on the magic endpoint
    async fn handle_magic_accept(
        connecting: Connecting,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
    ) -> anyhow::Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = get_remote_node_id(&connection)?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }

        // 1- Receives request message from quinn stream
        // 2- Forwards it to the (addrs) via UDP socket
        // 3- Receives response message back from UDP socket
        // 4- Forwards it back to the quinn stream
        udpconn::handle_udp_listen(addrs.as_slice(), r, s).await?;
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
            if let Err(cause) = handle_magic_accept(connecting, addrs, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
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
        Commands::ListenUdp(args) => listen_udp(args).await,
        Commands::Connect(args) => connect_stdio(args).await,
        Commands::ConnectTcp(args) => connect_tcp(args).await,
        Commands::ConnectUdp(args) => connect_udp(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1)
        }
    }
}
