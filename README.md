# Dumb pipe

This is an example to use [iroh](https://crates.io/crates/iroh) to create a dumb pipe to connect two machines with a QUIC connection.

Iroh will take care of hole punching and NAT traversal whenever possible, and fall back to a
relay if hole punching does not succeed.

It is also useful as a standalone tool for quick copy jobs.

This is inspired by the unix tool [netcat](https://en.wikipedia.org/wiki/Netcat). While netcat
works with IP addresses, dumbpipe works with 256 bit node ids and therefore is somewhat location transparent. In addition, connections are encrypted using TLS.

# Installation

```
cargo install dumbpipe
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
dumbpipe connect nodeealvvv4nwa522qhznqrblv6jxcrgnvpapvakxw5i6mwltmm6ps2r4aicamaakdu5wtjasadei2qdfuqjadakqk3t2ieq | ffplay -f mpegts -fflags nobuffer -framedrop -
```

- Adjust the ffmpeg options according to your local platform and video capture devices.
- Use ticket from sender side

## Forward development web server

You have a development webserver running on port 3000, and want to share it with
a colleague in another office or on the other side of the world.

### The web server
```
npm run dev
>    - Local:        http://localhost:3000
```

### The dumbpipe listener

*Listens* on a magic endpoint and forwards all incoming requests to the dev web
server that is listening on localhost on port 3000. Any number of connections can
flow through a single dumb pipe, but they will be separate local tcp connections.

```
dumbpipe listen-tcp --host localhost:3000
```
This command will output a ticket that can be used to connect.

### The dumbpipe connector

*Listens* on a tcp interface and port on the local machine. In this case on port 3001.
Forwards all incoming connections to the magic endpoint given in the ticket.

```
dumbpipe connect-tcp --addr 0.0.0.0:3001 <ticket>
```

### Testing it

You can now browse the website on port 3001.

# Advanced features

## Limiting access

You can limit access to a dumbpipe listener through a keys file, similar to the `authorized_keys` file that SSH uses.
You can put the file wherever you want, e.g. at `~/.dumbpipe/authorized_keys`. For the file to be used, and thus
access to be limited, specify the file path with the `--authorized-keys` (or `-a`) when launching dumbpipe.
When authorization is set, only connections from nodes listed in the file will be accepted.

Here's an example file:
```
# dumbpipe authorized nodes
148449487b53bb90382927634114457ef90d2a63127200fd8816a8dffb9d48c6 some-server
3827f5124d03d10f2f344d319a88c64c198c4db1335560ea6aad41ce2fb7c311 devbox
```

The file must contain a list of hex-encoded node ids, seperated by newlines.
The node ids may be followed by a comment, separated by a space from the encoded node id.
Lines starting with `#` are ignored and can be used as comments.

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
