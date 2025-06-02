use anyhow::{Context, Result};
use bytes::Bytes;
use dumbpipe::NodeTicket;
use iroh::{
    endpoint::{get_remote_node_id, Connecting},
    Endpoint,
};
use quinn::Connection;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
};
use tokio::{net::UdpSocket, select, signal};
use tokio_util::sync::CancellationToken;

use std::sync::Arc;

use crate::{get_or_create_secret, ConnectUdpArgs, ListenUdpArgs};

// 1- Receives request message from socket
// 2- Forwards it to the connection datagram
// 3- Receives response message back from connection datagram
// 4- Forwards it back to the socket
pub async fn connect_udp(args: ConnectUdpArgs) -> anyhow::Result<()> {
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
    let conns = Arc::new(tokio::sync::Mutex::new(
        HashMap::<SocketAddr, Connection>::new(),
    ));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                eprintln!("Received CTRL-C, shutting down...");
                break;
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((size, sock_addr)) => {
                        // Check if we already have a connection for this socket address
                        let mut cnns = conns.lock().await;
                        let connection = match cnns.get_mut(&sock_addr) {
                            Some(conn) => conn,
                            None => {
                                // If we don't have a connection, drop the previous lock to create a new one later on
                                drop(cnns);

                                // Create a new connection since this address is not in the hashmap
                                let endpoint = endpoint.clone();
                                let addr = node_addr.clone();
                                let handshake = !args.common.is_custom_alpn();
                                let alpn = args.common.alpn()?;

                                let remote_node_id = addr.node_id;
                                tracing::info!("creating a connection to be forwarding UDP to {}", remote_node_id);

                                // connect to the node, try only once
                                let connection = endpoint
                                    .connect(addr.clone(), &alpn)
                                    .await
                                    .context(format!("error connecting to {}", remote_node_id))?;
                                tracing::info!("connected to {}", remote_node_id);

                                // send the handshake unless we are using a custom alpn
                                if handshake {
                                    connection.send_datagram(Bytes::from_static(&dumbpipe::HANDSHAKE))?;
                                }

                                let sock_send = socket.clone();
                                let conn_clone = connection.clone();
                                let conns_clone = conns.clone();
                                // Spawn a task for listening the connection datagram, and forward the data to the UDP socket
                                tokio::spawn(async move {
                                    // 3- Receives response message back from connection datagram
                                    // 4- Forwards it back to the socket
                                    if let Err(cause) = handle_udp_accept(sock_addr, sock_send, conn_clone).await {
                                        // log error at warn level
                                        //
                                        // we should know about it, but it's not fatal
                                        tracing::warn!("error handling connection: {}", cause);
                                    }
                                    // Cleanup resources for this connection since it's `Connection` is closed or errored out
                                    let mut cn = conns_clone.lock().await;
                                    cn.remove(&sock_addr);
                                });

                                // Store the connection and return
                                let mut cn = conns.lock().await;
                                cn.insert(sock_addr, connection.clone());
                                &mut connection.clone()
                            }
                        };

                        // 1- Receives request message from socket
                        // 2- Forwards it to the connection datagram
                        if let Err(e) = connection.send_datagram(Bytes::copy_from_slice(&buf[..size])) { // Is Bytes::copy_from_slice most efficient way to do this?. Investigate.
                            tracing::error!("Error writing to connection datagram: {}", e);
                            return Err(e.into());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("error receiving from UDP socket: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Listen on a magicsocket and forward incoming connections to a udp socket.
pub async fn listen_udp(args: ListenUdpArgs) -> anyhow::Result<()> {
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
        if handshake {
            // read the handshake and verify it
            let bytes = connection.read_datagram().await?;
            anyhow::ensure!(*bytes == dumbpipe::HANDSHAKE, "invalid handshake");
        }

        // 1- Receives request message from connection datagram
        // 2- Forwards it to the (addrs) via UDP socket
        // 3- Receives response message back from UDP socket
        // 4- Forwards it back to the connection datagram
        handle_udp_listen(addrs.as_slice(), connection).await?;
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

async fn handle_udp_accept(
    client_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    connection: Connection,
) -> Result<()> {
    // Create a cancellation token to coordinate shutdown
    let token = CancellationToken::new();
    let token_conn = token.clone();
    let token_ctrl_c = token.clone();

    // Create buffer for receiving data
    let connection_to_udp = {
        let socket = udp_socket.clone();
        tokio::spawn(async move {
            loop {
                // Check if we should stop
                if token_conn.is_cancelled() {
                    break;
                }

                // Read from connection datagram
                match connection.read_datagram().await {
                    Ok(bytes) => {
                        // Forward to UDP peer
                        if let Err(e) = socket.send_to(&bytes, client_addr).await {
                            tracing::error!("Error sending to UDP: {}", e);
                            token_conn.cancel();
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Connection read_datagram error: {}", e);
                        token_conn.cancel();
                        break;
                    }
                }
            }
        })
    };

    // Handle Ctrl+C signal
    let ctrl_c = tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            token_ctrl_c.cancel();
        }
    });

    // Wait for any task to complete (or Ctrl+C)
    tokio::select! {
        _ = connection_to_udp => {},
        _ = ctrl_c => {},
    }

    Ok(())
}

// Every new connection is a new socket to the `connect udp` command
async fn handle_udp_listen(peer_addrs: &[SocketAddr], connection: Connection) -> Result<()> {
    // Create a cancellation token to coordinate shutdown
    let token = CancellationToken::new();
    let token_udp = token.clone();
    let token_conn = token.clone();
    let token_ctrl_c = token.clone();

    // Create a new socket for this connection, representing the client connected to UDP server at the other side.
    // This socket will be used to send data to the actual server, receive response back and forward it to the conn.
    let socket = Arc::new(UdpSocket::bind("0.0.0:0").await?);

    let udp_buf_size = 65535; // Maximum UDP packet size
    let conn_to_udp = {
        let socket_send = socket.clone();
        let p_addr = peer_addrs.to_vec();
        let conn_clone = connection.clone();
        tokio::spawn(async move {
            loop {
                // Check if we should stop
                if token_conn.is_cancelled() {
                    tracing::info!("Token cancellation was requested. Ending QUIC to UDP task.");
                    break;
                }

                // Read from connection datagram
                match conn_clone.read_datagram().await {
                    Ok(bytes) => {
                        // Forward to UDP peer
                        for addr in p_addr.iter() {
                            if let Err(e) = socket_send.send_to(&bytes, addr).await {
                                tracing::error!("Error sending to UDP: {}", e);
                                token_conn.cancel();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Connection read_datagram error: {}", e);
                        token_conn.cancel();
                        break;
                    }
                }
            }
            tracing::info!("Token cancellation was requested or error received. connection datagram task ended.");
        })
    };

    let udp_to_conn = {
        // Task for listening to the response to the UDP server
        let socket_listen = socket.clone();
        let conn_clone = connection.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_buf_size];
            loop {
                // Check if we should stop
                if token_udp.is_cancelled() {
                    tracing::info!("Token cancellation was requested. Ending UDP to QUIC task.");
                    break;
                }

                // Use timeout to periodically check cancellation
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    socket_listen.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _addr))) => {
                        // Forward the buf back to the connection datagram
                        if let Err(e) = conn_clone.send_datagram(Bytes::copy_from_slice(&buf[..n]))
                        {
                            tracing::error!("Error on connection send_datagram: {}", e);
                            token_udp.cancel();
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("UDP receive error: {}", e);
                        token_udp.cancel();
                        break;
                    }
                    Err(_) => continue, // Timeout, check cancellation
                }
            }
            tracing::info!(
                "Token cancellation was requested or error received. UDP socket task ended."
            );
        })
    };

    // Handle Ctrl+C signal
    let ctrl_c = tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            token_ctrl_c.cancel();
        }
    });

    // Wait for any task to complete (or Ctrl+C)
    tokio::select! {
        _ = conn_to_udp => {},
        _ = udp_to_conn => {},
        _ = ctrl_c => {},
    }

    Ok(())
}
