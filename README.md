# Dumb pipe

This is an example to use iroh-net to create a dumb pipe to connect two machines
with a QUIC connection.

It is also useful as a standalone tool for quick copy jobs.

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
connect-tcp --addr 0.0.0.0:3001 <ticket>
```

### Testing it

You can now browse the website on port 3001.

# Need a dumb pipe as well?

Dumb pipe is a very simple command line tool that uses [iroh](https://github.com/n0-computer/iroh) .
