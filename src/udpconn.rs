use std::net::SocketAddr;
use tokio::net::UdpSocket;
use quinn::{RecvStream, SendStream};
use anyhow::Result;
use tokio_util::sync::CancellationToken;

use std::sync::Arc;

pub(crate) async fn handle_udp_accept(
    client_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    mut recv_stream: RecvStream,
) -> Result<()> {
    // Create a cancellation token to coordinate shutdown
    let token = CancellationToken::new();
    let token_quinn = token.clone();
    let token_ctrl_c = token.clone();

    // Create buffer for receiving data
    let udp_buf_size = 65535; // Maximum UDP packet size
    let quinn_to_udp = {
        let socket = udp_socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_buf_size];
            loop {
                // Check if we should stop
                if token_quinn.is_cancelled() {
                    break;
                }

                // Read from Quinn stream
                match recv_stream.read(&mut buf).await {
                    Ok(Some(n)) => {
                        // Parse the prefixed message to get the address and the buff
                        // let (addr, buf) = read_prefixed_message(&buf[..n]).unwrap();
                        tracing::info!("forward_udp_to_quinn: Received {} bytes from quinn stream.", n);
                        
                        // Forward to UDP peer
                        tracing::info!("Parsed packet from quinn stream. Forwarding to {}", client_addr);
                        if let Err(e) = socket.send_to(&buf[..n], client_addr).await {
                            eprintln!("Error sending to UDP: {}", e);
                            token_quinn.cancel();
                            break;
                        }
                    }
                    Ok(None) => {
                        // Quinn stream ended normally
                        token_quinn.cancel();
                        break;
                    }
                    Err(e) => {
                        eprintln!("Quinn receive error: {}", e);
                        token_quinn.cancel();
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
        // _ = udp_to_quinn => {},
        _ = quinn_to_udp => {},
        _ = ctrl_c => {},
    }

    Ok(())
}

// Every new connection is a new socket to the `connect udp` command
pub(crate) async fn handle_udp_listen(
    peer_addrs: &[SocketAddr],
    mut recv_stream: RecvStream,
    mut send_stream: SendStream,
) -> Result<()> {
    // Create a cancellation token to coordinate shutdown
    let token = CancellationToken::new();
    let token_udp = token.clone();
    let token_quinn = token.clone();
    let token_ctrl_c = token.clone();

    // Create a new socket for this connection, representing the client connected to UDP server at the other side.
    // This socket will be used to send data to the actual server, receive response back and forward it to the conn.
    let socket = Arc::new(UdpSocket::bind("0.0.0:0").await?);

    let udp_buf_size = 65535; // Maximum UDP packet size
    let quinn_to_udp = {
        let socket_send = socket.clone();
        let p_addr = peer_addrs.to_vec();
        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_buf_size];
            loop {
                // Check if we should stop
                if token_quinn.is_cancelled() {
                    tracing::info!("Token cancellation was requested. Ending QUIC to UDP task.");
                    break;
                }

                // Read from Quinn stream
                match recv_stream.read(&mut buf).await {
                    Ok(Some(n)) => {
                        tracing::info!("forward_quinn_to_udp: Received {} bytes from quinn stream.", n);

                        // Forward to UDP peer
                        // tracing::info!("Forwarding packets to {:?}", peer_addrs);
                        for addr in p_addr.iter() {
                            if let Err(e) = socket_send.send_to(&buf[..n], addr).await {
                                eprintln!("Error sending to UDP: {}", e);
                                token_quinn.cancel();
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        // Quinn stream ended normally
                        token_quinn.cancel();
                        break;
                    }
                    Err(e) => {
                        eprintln!("Quinn receive error: {}", e);
                        token_quinn.cancel();
                        break;
                    }
                }
            }
            tracing::info!("Token cancellation was requested or error received. quinn connection task ended.");
        })
    };
    
    let udp_to_quinn = {
        // Task for listening to the response to the UDP server
        let socket_listen = socket.clone();
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
                        tracing::info!("forward_quinn_to_udp: Received {} bytes from server", n);

                        // Forward the buf back to the quinn stream
                        if let Err(e) = send_stream.write_all(&buf[..n]).await {
                            eprintln!("Error writing to Quinn stream: {}", e);
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
        _ = quinn_to_udp => {},
        _ = udp_to_quinn => {},
        _ = ctrl_c => {},
    }

    Ok(())
}
