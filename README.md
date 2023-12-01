# Dumb pipe

This is an example to use iroh-net to create a dumb pipe to connect two machines
with a QUIC connection.

It is also useful as a standalone tool for quick copy jobs.

# Example

Use dumbpipe to stream video using [ffmpeg / ffplay](https://ffmpeg.org/):

## Sender side
```
ffmpeg -f avfoundation -r 30 -i "0" -pix_fmt yuv420p -f mpegts - | dumbpipe listen
```
outputs ticket

## Receiver side
```
dumbpipe connect nodeealvvv4nwa522qhznqrblv6jxcrgnvpapvakxw5i6mwltmm6ps2r4aicamaakdu5wtjasadei2qdfuqjadakqk3t2ieq | ffplay -f mpegts -fflags nobuffer -framedrop -
```

- Adjust the ffmpeg options according to your local platform and video capture devices.
- Use ticket from sender side