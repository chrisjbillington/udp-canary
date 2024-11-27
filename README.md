udp-canary.py
=============

Simple script to log UDP connectivity between peers, with a traffic pattern similar to a
typical Wireguard setup for the case where a peer is behind NAT.

why
---

ISPs that use CG-NAT sometimes have configurations that are not ideal for long-lived UDP
traffic between the same ports, which can cause causing wireguard connectivity problems.
These are hard to debug as they are hard to reproduce.

This script creates UDP traffic similar to what you would get using Wireguard with one
peer behind NAT and the other having a public IP address. Logging this data to attempt
to monitor UDP connectivity is easier than doing actual packet capture of the Wireguard
traffic you're interested in.

how
---

The script runs as either `--client` or `--server`. The server can handle multiple
clients - just be sure to give each a unique `--id`.

**Protocol**:

The client sends a `'handshake_init'` message every five seconds until it gets a
matching `'handshake_response'` from the server. It then sends a `"keepalive"` message,
then further `"keepalive"` messages every 26.625 seconds. After five keepalives it
starts again by sending a new `"handshake_init"` message.

The server replies to `'handshake_init'` messages as long as they appear newer than the
most recent `'handshake_init'` it has seen from the client with that id. It does not
reply to keepalives.

All sent and received messages are logged for later analysis of connectivity.

Messages are encrypted and authenticated with AES128 CBC + SHA256 HMAC, to ensure only
traffic between peers with the same preshared key is interpreted as demonstrating
connectivity. You can generate a key by running with `--generate-key`.

All messages are unique which allows detection of replayed traffic, which is still
possible despite encryption/authentication of messages. All received messages are
logged, but messages that look like replays are not otherwise acted on.

Messages are json strings and look like this:

`'handshake_init'`:
```
{'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732670965, 0]}
```
Sent from clients to the server. The first element of `'data'` is the handshake id, an
integer that starts at the current unix timestamp when the client starts, and then
increments by one per `handshake_init` message. The second element of `'data'` is always
zero.

`'handshake_response'`:
```
{'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732670965, 0]}
```
Sent from the server to clients, in response to `'handshake_init'` messages, as long as
the handshake id is greater than the unix timestamp at which the server started running,
and greater than the highest previously-seen handshake id from hat client id. Response
message is identical to the message being replied to, other than with `'type'` set to
`'handshake_response'`.

`'keepalive'`:
```
{'id': 'my-client-id', 'type': 'keepalive', 'data': [1732670965, 1]}
```
Sent from clients to the server. The first element of `'data'` is the most recent
handshake id for which the client received a response. The second element of `'data'` is
the keepalive counter, which starts at 1 after a sucessful handshake and increments by 1
for each subsequent keepalive until the next handshake.


run
---

Easiest way is to clone this repo and create a Python virtual environment:

```bash
git clone https://github.com/chrisjbillington/udp-canary
cd udp-canary
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# server:
python udp-canary.py --generate-key
python udp-canary.py --server --key <your-key-here>

# client:
python udp-canary.py --client --id <your-client-name> --host <your-server-ipv4-address> --key <your-key-here>
```

log
---

Activity is by default logged to `udp-canary.log` in the current directory and to the console.

Normal output looks like this for a client:

```shell
$ python udp-canary.py --generate-key
DP2hvII7udFu0b2DBvmrxw==
$ python udp-canary.py --server --key DP2hvII7udFu0b2DBvmrxw==
[2024-11-27 13:06:33.401 udp-canary INFO] Listening on 0.0.0.0:43210
[2024-11-27 13:06:56.795 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673217, 0]}
[2024-11-27 13:06:56.795 udp-canary INFO] TX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673217, 0]}
[2024-11-27 13:06:56.795 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 1]}
[2024-11-27 13:07:23.448 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 2]}
[2024-11-27 13:07:50.097 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 3]}
[2024-11-27 13:08:16.749 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 4]}
[2024-11-27 13:08:43.401 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 5]}
[2024-11-27 13:08:43.401 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673218, 0]}
[2024-11-27 13:08:43.401 udp-canary INFO] TX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673218, 0]}
[2024-11-27 13:08:43.402 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 1]}
[2024-11-27 13:09:10.054 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 2]}
[2024-11-27 13:09:36.697 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 3]}
[2024-11-27 13:10:03.348 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 4]}
[2024-11-27 13:10:29.997 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 5]}
[2024-11-27 13:10:29.997 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673219, 0]}
[2024-11-27 13:10:29.998 udp-canary INFO] TX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673219, 0]}
[2024-11-27 13:10:29.998 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673219, 1]}
[2024-11-27 13:10:56.648 udp-canary INFO] RX 127.0.0.1:46668 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673219, 2]}
```

And for a server:
```shell
$ python udp-canary.py --client --id my-client-id --host 127.0.0.1 --key DP2hvII7udFu0b2DBvmrxw==
[2024-11-27 13:06:56.793 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673217, 0]}
[2024-11-27 13:06:56.795 udp-canary INFO] RX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673217, 0]}
[2024-11-27 13:06:56.795 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 1]}
[2024-11-27 13:07:23.447 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 2]}
[2024-11-27 13:07:50.097 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 3]}
[2024-11-27 13:08:16.749 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 4]}
[2024-11-27 13:08:43.400 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673217, 5]}
[2024-11-27 13:08:43.401 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673218, 0]}
[2024-11-27 13:08:43.402 udp-canary INFO] RX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673218, 0]}
[2024-11-27 13:08:43.402 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 1]}
[2024-11-27 13:09:10.054 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 2]}
[2024-11-27 13:09:36.697 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 3]}
[2024-11-27 13:10:03.347 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 4]}
[2024-11-27 13:10:29.997 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673218, 5]}
[2024-11-27 13:10:29.997 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_init', 'data': [1732673219, 0]}
[2024-11-27 13:10:29.998 udp-canary INFO] RX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'handshake_response', 'data': [1732673219, 0]}
[2024-11-27 13:10:29.998 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673219, 1]}
[2024-11-27 13:10:56.647 udp-canary INFO] TX 127.0.0.1:43210 {'id': 'my-client-id', 'type': 'keepalive', 'data': [1732673219, 2]}
```

help
----

```
usage: udp-canary.py [-h] (--client | --server | --generate-key) [--id ID]
                     [--host HOST] [--port PORT] [--key KEY] [--log LOG]

UDP connectivity monitor

options:
  -h, --help      show this help message and exit
  --client        run client
  --server        run server
  --generate-key  generate and output an encryption encryption/authentication
                  key, and exit
  --id ID         unique client id string
  --host HOST     client: IPv4 address of server, server: bind address
                  (server, default: 0.0.0.0)
  --port PORT     Server UDP port, default 43210
  --key KEY       16-byte, base64-encoded encryption/authentication key, as
                  output by --generate-key
  --log LOG       log filepath (default: udp-canary.log)
```
