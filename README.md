# Dumb pipe

This is an example to use [iroh](https://crates.io/crates/iroh) to create a dumb pipe to connect two machines with a QUIC connection.

Iroh will take care of hole punching and NAT traversal whenever possible, and fall back to a
relay if hole punching does not succeed.

It is also useful as a standalone tool for quick copy jobs.

This is inspired by the unix tool [netcat](https://en.wikipedia.org/wiki/Netcat). While netcat
works with IP addresses, dumbpipe works with 256 bit endpoint ids and therefore is somewhat location transparent. In addition, connections are encrypted using TLS.

# Installation

With [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html):

```
cargo install dumbpipe
```

If you've installed [Homebrew](https://brew.sh), you can install it using the following command:

```
brew install dumbpipe
```

# Examples

## Use dumbpipe to stream video using [ffmpeg / ffplay](https://ffmpeg.org/):

This is using standard input and output.

### Sender side

On Mac OS:
```
ffmpeg -f avfoundation -r 30 -i "0" -pix_fmt yuv420p -f mpegts - | dumbpipe listen
```
On Linux:
```
ffmpeg -f v4l2 -i /dev/video0 -r 30 -preset ultrafast -vcodec libx264 -tune zerolatency -f mpegts - | dumbpipe listen
```
outputs ticket

### Receiver side
```
dumbpipe connect endpointealvvv4nwa522qhznqrblv6jxcrgnvpapvakxw5i6mwltmm6ps2r4aicamaakdu5wtjasadei2qdfuqjadakqk3t2ieq | ffplay -f mpegts -fflags nobuffer -framedrop -
```

- Adjust the ffmpeg options according to your local platform and video capture devices.
- Use ticket from sender side

## Share a shell for pair- or ensemble programming with [tty-share](https://github.com/elisescu/tty-share):

Sharing a terminal session over the internet is useful for collaboration between programmers, but the public [tty-share](https://github.com/elisescu/tty-share) server isn't very reliable and, more importantly, [it is not end-to-end encrypted](https://tty-share.com/how-it-works/#end-to-end-encryption).

On the server:

```
$ dumbpipe listen-tcp --host localhost:8000 &
$ tty-share
```

On the client(s):

```
$ dumbpipe connect-tcp --addr localhost:8000 <ticket> &
$ tty-share http://localhost:8000/s/local/
```

## Forward development web server

You have a development webserver running on port 3000, and want to share it with
a colleague in another office or on the other side of the world.

### The web server
```
npm run dev
>    - Local:        http://localhost:3000
```

### The dumbpipe listener

*Listens* on an endpoint and forwards all incoming requests to the dev web
server that is listening on localhost on port 3000. Any number of connections can
flow through a single dumb pipe, but they will be separate local tcp connections.

```
dumbpipe listen-tcp --host localhost:3000
```
This command will output a ticket that can be used to connect.

### The dumbpipe connector

*Listens* on a tcp interface and port on the local machine. In this case on port 3001.
Forwards all incoming connections to the endpoint given in the ticket.

```
dumbpipe connect-tcp --addr 0.0.0.0:3001 <ticket>
```

### Testing it

You can now browse the website on port 3001.

## Forward a Unix Socket Application (e.g., Zellij)

You can forward applications that communicate over Unix sockets, like the terminal multiplexer [Zellij](https://zellij.dev/).

Note: Zellij keeps its session sockets under `$ZELLIJ_SOCKET_DIR/<VERSION>/session-name`

![image](https://github.com/user-attachments/assets/b8fbb988-57db-40cd-95e2-208e01fbaad6)

1. On the remote host (with Zellij running):

```bash
zellij --version
# zellij 0.42.2
# Forward the remote Zellij socket
# Socket path follows pattern: /tmp/zellij-0/<VERSION>/<session-name>
dumbpipe listen-unix --socket-path /tmp/zellij-0/0.42.2/remote-task-1234
```

This will give you a `<ticket>`.

2. On your local machine:

```bash
zellij --version
# zellij 0.42.1

# Create the local socket directory structure
mkdir -p /tmp/zj-remote/0.42.1

# Create a local socket connected to the remote one
dumbpipe connect-unix --socket-path /tmp/zj-remote/0.42.1/remote-task-1234 <ticket>
```

3. Attach your local Zellij client:

```bash
# In a new terminal window/tab, set the socket directory and attach
ZELLIJ_SOCKET_DIR=/tmp/zj-remote zellij attach remote-task-1234
```

# Advanced features

## Combining Listeners

You can mix and match listeners. For example, forward from a remote Unix socket to a local TCP port:

```bash
# Machine A: Listen on a Unix socket
dumbpipe listen-unix --socket-path /var/run/my-app.sock

# Machine B: Connect to it via a local TCP port
dumbpipe connect-tcp --addr 127.0.0.1:8080 <ticket>
```

## Custom ALPNs

Dumbpipe has an expert feature to specify a custom [ALPN](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation) string. You can use it to interact with
existing iroh services.

E.g. here is how to interact with the iroh-blobs
protocol:

```
echo request1.bin | dumbpipe connect <ticket> --custom-alpn utf8:/iroh-bytes/2 > response1.bin
```

(`/iroh-bytes/2` is the ALPN string for the iroh-blobs protocol, which used to be called iroh-bytes.)

if request1.bin contained a valid request for the `/iroh-bytes/2` protocol, response1.bin will
now contain the response.
