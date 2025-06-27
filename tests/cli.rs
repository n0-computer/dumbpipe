#![cfg_attr(target_os = "windows", allow(unused_imports, dead_code))]
use dumbpipe::NodeTicket;
use rand::Rng;

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    str::FromStr,
    sync::{Arc, Barrier},
    time::Duration,
};

// binary path
fn dumbpipe_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dumbpipe")
}

/// Read `n` lines from `reader`, returning the bytes read including the newlines.
///
/// This assumes that the header lines are ASCII and can be parsed byte by byte.
fn read_ascii_lines(mut n: usize, reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    let mut res = Vec::new();
    loop {
        if reader.read(&mut buf)? != 1 {
            break;
        }
        let char = buf[0];
        res.push(char);
        if char != b'\n' {
            continue;
        }
        if n > 1 {
            n -= 1;
        } else {
            break;
        }
    }
    Ok(res)
}

fn wait2() -> Arc<Barrier> {
    Arc::new(Barrier::new(2))
}

/// generate a random, non privileged port
fn random_port() -> u16 {
    rand::thread_rng().gen_range(10000u16..60000)
}

/// Tests the basic functionality of the connect and listen pair
///
/// Connect and listen both write a limited amount of data and then EOF.
/// The interaction should stop when both sides have EOF'd.
#[test]
#[ignore = "flaky"]
fn connect_listen_happy() {
    // the bytes provided by the listen command
    let listen_to_connect = b"hello from listen";
    let connect_to_listen = b"hello from connect";
    let mut listen = duct::cmd(dumbpipe_bin(), ["listen"])
        .env_remove("RUST_LOG") // disable tracing
        .stdin_bytes(listen_to_connect)
        .stderr_to_stdout() //
        .reader()
        .unwrap();
    // read the first 3 lines of the header, and parse the last token as a ticket
    let header = read_ascii_lines(3, &mut listen).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();

    let connect = duct::cmd(dumbpipe_bin(), ["connect", &ticket.to_string()])
        .env_remove("RUST_LOG") // disable tracing
        .stdin_bytes(connect_to_listen)
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, listen_to_connect);

    let mut listen_stdout = Vec::new();
    listen.read_to_end(&mut listen_stdout).unwrap();
    assert_eq!(&listen_stdout, connect_to_listen);
}

/// Tests the basic functionality of the connect and listen pair
///
/// Connect and listen both write a limited amount of data and then EOF.
/// The interaction should stop when both sides have EOF'd.
#[test]
#[ignore = "flaky"]
fn connect_listen_custom_alpn_happy() {
    // the bytes provided by the listen command
    let listen_to_connect = b"hello from listen";
    let connect_to_listen = b"hello from connect";
    let mut listen = duct::cmd(
        dumbpipe_bin(),
        ["listen", "--custom-alpn", "utf8:mysuperalpn/0.1.0"],
    )
    .env_remove("RUST_LOG") // disable tracing
    .stdin_bytes(listen_to_connect)
    .stderr_to_stdout() //
    .reader()
    .unwrap();
    // read the first 3 lines of the header, and parse the last token as a ticket
    let header = read_ascii_lines(3, &mut listen).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();

    let connect = duct::cmd(
        dumbpipe_bin(),
        [
            "connect",
            &ticket.to_string(),
            "--custom-alpn",
            "utf8:mysuperalpn/0.1.0",
        ],
    )
    .env_remove("RUST_LOG") // disable tracing
    .stdin_bytes(connect_to_listen)
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, listen_to_connect);

    let mut listen_stdout = Vec::new();
    listen.read_to_end(&mut listen_stdout).unwrap();
    assert_eq!(&listen_stdout, connect_to_listen);
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_connect() {
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };
    // the bytes provided by the listen command
    let mut listen = duct::cmd(dumbpipe_bin(), ["listen"])
        .env_remove("RUST_LOG") // disable tracing
        .stdin_bytes(b"hello from listen\n")
        .stderr_to_stdout() //
        .reader()
        .unwrap();
    // read the first 3 lines of the header, and parse the last token as a ticket
    let header = read_ascii_lines(3, &mut listen).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();

    let mut connect = duct::cmd(dumbpipe_bin(), ["connect", &ticket.to_string()])
        .env_remove("RUST_LOG") // disable tracing
        .stderr_null()
        .stdout_capture()
        .reader()
        .unwrap();
    // wait until we get a line from the listen process
    read_ascii_lines(1, &mut connect).unwrap();
    for pid in connect.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    // we don't care about the results. This test is just to make sure that the
    // listen command stops when the connect command stops.
    listen.read_to_end(&mut tmp).ok();
    connect.read_to_end(&mut tmp).ok();
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_listen() {
    use std::time::Duration;

    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };
    // the bytes provided by the listen command
    let mut listen = duct::cmd(dumbpipe_bin(), ["listen"])
        .env_remove("RUST_LOG") // disable tracing
        .stderr_to_stdout()
        .reader()
        .unwrap();
    // read the first 3 lines of the header, and parse the last token as a ticket
    let header = read_ascii_lines(3, &mut listen).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();

    let mut connect = duct::cmd(dumbpipe_bin(), ["connect", &ticket.to_string()])
        .env_remove("RUST_LOG") // disable tracing
        .stderr_null()
        .stdout_capture()
        .reader()
        .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    for pid in listen.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    // we don't care about the results. This test is just to make sure that the
    // listen command stops when the connect command stops.
    listen.read_to_end(&mut tmp).ok();
    connect.read_to_end(&mut tmp).ok();
}

// TODO: figure out why this is flaky on windows
#[test]
#[cfg(unix)]
#[ignore = "flaky"]
fn listen_tcp_happy() {
    let b1 = wait2();
    let b2 = b1.clone();
    let port = random_port();
    // start a dummy tcp server and wait for a single incoming connection
    let host_port = format!("localhost:{port}");
    let host_port_2 = host_port.clone();
    std::thread::spawn(move || {
        let server = TcpListener::bind(host_port_2).unwrap();
        b1.wait();
        let (mut stream, _addr) = server.accept().unwrap();
        stream.write_all(b"hello from tcp").unwrap();
        stream.flush().unwrap();
        drop(stream);
    });
    // wait for the tcp listener to start
    b2.wait();
    // start a dumbpipe listen-tcp process
    let mut listen_tcp = duct::cmd(dumbpipe_bin(), ["listen-tcp", "--host", &host_port])
        .env_remove("RUST_LOG") // disable tracing
        .stderr_to_stdout() //
        .reader()
        .unwrap();
    let header = read_ascii_lines(4, &mut listen_tcp).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();
    // poke the listen-tcp process with a connect command
    let connect = duct::cmd(dumbpipe_bin(), ["connect", &ticket.to_string()])
        .env_remove("RUST_LOG") // disable tracing
        .stderr_null()
        .stdout_capture()
        .stdin_bytes(b"hello from connect")
        .run()
        .unwrap();
    assert!(connect.status.success());
    assert_eq!(&connect.stdout, b"hello from tcp");
}

#[test]
fn connect_tcp_happy() {
    let port = random_port();
    let host_port = format!("localhost:{port}");
    // start a dumbpipe listen process just so the connect-tcp command has something to connect to
    let mut listen = duct::cmd(dumbpipe_bin(), ["listen"])
        .env_remove("RUST_LOG") // disable tracing
        .stdin_bytes(b"hello from listen\n")
        .stderr_to_stdout() //
        .reader()
        .unwrap();
    let header = read_ascii_lines(3, &mut listen).unwrap();
    let header = String::from_utf8(header).unwrap();
    let ticket = header.split_ascii_whitespace().last().unwrap();
    let ticket = NodeTicket::from_str(ticket).unwrap();
    let ticket = ticket.to_string();

    // start a dumbpipe connect-tcp process
    let _connect_tcp = duct::cmd(
        dumbpipe_bin(),
        ["connect-tcp", "--addr", &host_port, &ticket],
    )
    .env_remove("RUST_LOG") // disable tracing
    .stderr_to_stdout() //
    .reader()
    .unwrap();
    std::thread::sleep(Duration::from_secs(1));

    //
    let mut conn = TcpStream::connect(host_port).unwrap();
    conn.write_all(b"hello from tcp").unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf, b"hello from listen\n");
}

#[cfg(unix)]
mod unix_socket_tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Generate a temp directory with a Unix socket path
    fn temp_socket_path() -> (TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        (temp_dir, socket_path)
    }

    /// A dummy unix server that accepts multiple connections and handles them properly.
    fn dummy_unix_server(
        socket_path: PathBuf,
        barrier: Arc<Barrier>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let listener = match std::os::unix::net::UnixListener::bind(&socket_path) {
                Ok(l) => l,
                Err(e) => {
                    // Don't panic here, just print an error and exit the thread.
                    eprintln!("Dummy server failed to bind: {e:?}");
                    return;
                }
            };
            barrier.wait();
            // Accept connections in a loop
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    // Handle each connection in a new thread
                    std::thread::spawn(move || {
                        if std::io::Write::write_all(&mut stream, b"hello from unix").is_err() {
                            return;
                        }
                        if std::io::Write::flush(&mut stream).is_err() {
                            return;
                        }
                        // Shut down the write half of the stream to signal EOF.
                        stream.shutdown(std::net::Shutdown::Write).ok();
                        // Read and discard any remaining data from the client.
                        std::io::copy(&mut stream, &mut std::io::sink()).ok();
                    });
                } else {
                    // Stop listening on error
                    break;
                }
            }
        })
    }

    #[test]
    fn listen_unix_happy() {
        let (_temp_dir, socket_path) = temp_socket_path();
        let b1 = wait2();
        let b2 = b1.clone();

        // Start the dummy unix server in the background.
        let server_thread = dummy_unix_server(socket_path.clone(), b1);

        // Wait for the unix listener to start.
        b2.wait();

        // Start a dumbpipe listen-unix process.
        let mut listen_unix_handle = duct::cmd(
            dumbpipe_bin(),
            [
                "listen-unix",
                "--socket-path",
                socket_path.to_str().unwrap(),
            ],
        )
        .env_remove("RUST_LOG") // disable tracing
        .stderr_to_stdout()
        .reader()
        .unwrap();

        // Read the ticket from the listener's output.
        let header = read_ascii_lines(4, &mut listen_unix_handle).unwrap();
        let header = String::from_utf8(header).unwrap();
        let ticket = header.split_ascii_whitespace().last().unwrap();
        let ticket = NodeTicket::from_str(ticket).unwrap();

        // Poke the listen-unix process with a connect command, retrying on failure.
        let mut connect_output = None;
        for _ in 0..10 {
            let connect_cmd = duct::cmd(dumbpipe_bin(), ["connect", &ticket.to_string()])
                .env_remove("RUST_LOG") // disable tracing
                .stdin_bytes(b"hello from connect")
                .stdout_capture()
                .stderr_capture()
                .unchecked();

            if let Ok(c) = connect_cmd.run() {
                if c.status.success() {
                    connect_output = Some(c);
                    break;
                }
            }
            // If it failed, wait a bit before retrying.
            std::thread::sleep(Duration::from_millis(500));
        }
        let connect = connect_output.expect("failed to connect within the retry loop");

        assert!(connect.status.success());
        assert_eq!(&connect.stdout, b"hello from unix");

        // Explicitly kill the listener process to ensure cleanup.
        listen_unix_handle.kill().ok();
        // The server thread will die when the main test process exits.
        drop(server_thread);
    }

    #[test]
    fn connect_unix_happy() {
        let (_temp_dir, socket_path) = temp_socket_path();
        let b1 = wait2();
        let b2 = b1.clone();
        let socket_path_clone = socket_path.clone();

        // Start a dumbpipe listen process in background
        let listen_thread = std::thread::spawn(move || {
            let mut listen = duct::cmd(dumbpipe_bin(), ["listen"])
                .env_remove("RUST_LOG")
                .stdin_bytes(b"hello from magic")
                .stderr_to_stdout()
                .reader()
                .unwrap();

            // Parse ticket from header
            let header = read_ascii_lines(3, &mut listen).unwrap();
            let header = String::from_utf8(header).unwrap();
            let ticket = header.split_ascii_whitespace().last().unwrap();

            b1.wait(); // Signal that ticket is ready

            // Start connect-unix process
            let _connect_unix = duct::cmd(
                dumbpipe_bin(),
                [
                    "connect-unix",
                    "--socket-path",
                    socket_path_clone.to_str().unwrap(),
                    ticket,
                ],
            )
            .env_remove("RUST_LOG")
            .start()
            .unwrap();

            std::thread::sleep(Duration::from_secs(2));
        });

        // Wait for ticket to be ready
        b2.wait();

        // Give connect-unix time to set up Unix socket
        std::thread::sleep(Duration::from_millis(500));

        // Connect to Unix socket and test data flow
        let mut unix_stream = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        std::io::Write::write_all(&mut unix_stream, b"hello from unix").unwrap();
        std::io::Write::flush(&mut unix_stream).unwrap();

        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut unix_stream, &mut buf).unwrap();
        assert_eq!(&buf, b"hello from magic");

        listen_thread.join().unwrap();
    }
}
