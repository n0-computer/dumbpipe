/// The ALPN for dumbpipe.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send a fixed size handshake to make sure the stream is created.
pub const ALPN: &[u8] = b"DUMBPIPEV0";

/// The handshake to send when connecting.
///
/// The side that calls open_bi() first must send this handshake, the side that
/// calls accept_bi() must consume it.
pub const HANDSHAKE: [u8; 5] = *b"hello";

/// The handshake prefix for named connections used by the daemon.
///
/// A single iroh endpoint can multiplex several named tunnels, so the
/// accepting side must learn which backend an incoming stream belongs to.
/// The connecting side opens a bidi stream and writes this prefix, followed
/// by the name length as a big-endian [`u32`], followed by the UTF-8 name:
///
/// ```text
/// HANDSHAKE_NAMED ("named") || name_len: u32 big-endian || name (UTF-8)
/// ```
///
/// It replaces [`HANDSHAKE`] for daemon streams.
pub const HANDSHAKE_NAMED: [u8; 5] = *b"named";

pub use iroh_tickets::endpoint::EndpointTicket;
