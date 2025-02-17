use std::net::SocketAddr;
use bytes::Bytes;
use tokio::net::UdpSocket;
use quinn::Connection;
use anyhow::Result;
use tokio_util::sync::CancellationToken;

use std::sync::Arc;

pub(crate) async fn handle_udp_accept(
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
                        let n = bytes.len(); // TODO: remove this line
                        tracing::info!("read datagram from connection with {} bytes. Forwarding to {}", n, client_addr);

                        // Forward to UDP peer
                        if let Err(e) = socket.send_to(&bytes, client_addr).await {
                            eprintln!("Error sending to UDP: {}", e);
                            token_conn.cancel();
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection read_datagram error: {}", e);
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
pub(crate) async fn handle_udp_listen(
    peer_addrs: &[SocketAddr],
    connection: Connection,
) -> Result<()> {
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
                        let n = bytes.len(); // TODO: remove this line
                        tracing::info!("conn_to_udp: Received {} bytes from datagram stream.", n);

                        // Forward to UDP peer
                        for addr in p_addr.iter() {
                            if let Err(e) = socket_send.send_to(&bytes, addr).await {
                                eprintln!("Error sending to UDP: {}", e);
                                token_conn.cancel();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection read_datagram error: {}", e);
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
                    socket_listen.recv_from(&mut buf)
                ).await {
                    Ok(Ok((n, _addr))) => {
                        tracing::info!("udp_to_conn: Received {} bytes from server", n);

                        // Forward the buf back to the connection datagram
                        if let Err(e) = conn_clone.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                            eprintln!("Error on connection send_datagram: {}", e);
                            token_udp.cancel();
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("UDP receive error: {}", e);
                        token_udp.cancel();
                        break;
                    }
                    Err(_) => continue, // Timeout, check cancellation
                }
            }
            tracing::info!("Token cancellation was requested or error received. UDP socket task ended.");
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
