import sys
import socket
import json
import time
from select import poll, POLLIN
import os
import base64
import hmac
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


def generate_key():
    return base64.b64encode(os.urandom(16)).decode('utf-8')


class InvalidMessage(ValueError):
    pass


class Encryption:
    def __init__(self, key):
        self._key = base64.b64decode(key)
        if len(self._key) != 16:
            raise ValueError("Key must be 16 bytes")

    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        msg = iv + ciphertext
        h = hmac.new(self._key, msg, hashlib.sha256)
        hmac_value = h.digest()
        return msg + hmac_value

    def decrypt(self, data):
        # Verify HMAC
        h = hmac.new(self._key, data[:-32], hashlib.sha256)
        hmac_value = h.digest()
        if not hmac.compare_digest(hmac_value, data[-32:]):
            raise InvalidMessage
        iv = data[:16]
        ciphertext = data[16:-32]
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        return unpad(padded_plaintext, AES.block_size)


class EncryptedUDPComms:
    """Class for sending encrypted and authenticated (AES128 CBC + SHA256 HMAC)) data
    over UDP using the pre-shared key, which should be 16 bytes in base64 as returned by
    generate_key(). bind_addr, if not None, should be a (ipv4_address, port) tuple.
    """

    BUFFER = 4096

    def __init__(self, key, bind_addr=None, logger=None):
        self._logger = logger
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind_addr is not None:
            self._sock.bind(bind_addr)
            if self._logger is not None:
                self._logger.info(f"Listening on {bind_addr[0]}:{bind_addr[1]}")
        self.poller = poll()
        self.poller.register(self._sock, POLLIN)
        self._encryption = Encryption(key)

    def _packmsg(self, msg):
        return self._encryption.encrypt(json.dumps(msg).encode('utf8'))

    def _unpackmsg(self, msg):
        return json.loads(self._encryption.decrypt(msg).decode('utf8'))

    def sendmsg(self, msg, dst_ip, dst_port):
        """Send a json-serialisable object `msgdata` to the given UDP IP and port"""
        packedmsg = self._packmsg(msg)
        if self._logger is not None:
            self._logger.info(f"TX {dst_ip}:{dst_port} {msg}")
        try:
            self._sock.sendto(packedmsg, (dst_ip, dst_port))
        except Exception as e:
            if self._logger is not None:
                self._logger.warning(f"sendto: {str(e)}")

    def recvmsg(self):
        msg, (ip, port) = self._sock.recvfrom(self.BUFFER)
        try:
            msgdata = self._unpackmsg(msg)
            if self._logger is not None:
                self._logger.info(f"RX {ip}:{port} {msgdata}")
            return msgdata, (ip, port)
        except InvalidMessage:
            if self._logger is not None:
                self._logger.info(f"RX {ip}:{port} [InvalidMessage]")
            raise


class Server:
    DEFAULT_PORT = 43210
    def __init__(self, bind_ip, port, key, logger=None):
        self.port = port
        self.client_handshake_id = {}
        self.comms = EncryptedUDPComms(key, (bind_ip, port), logger=logger)
        self.t0 = int(time.time())

    def do_receive(self):
        try:
            msg, (ip, port) = self.comms.recvmsg()
        except InvalidMessage:
            return
        if msg['type'] == 'handshake_init':
            # Reply to non-replayed handshake initiations:
            client_id = msg['id']
            handshake_id = msg['data'][0]
            if handshake_id > self.client_handshake_id.get(client_id, 0):
                self.client_handshake_id[client_id] = handshake_id
                msg['type'] = 'handshake_response'
                self.comms.sendmsg(msg, ip, port)

    def run(self):
        while True:
            self.do_receive()


class Client:
    KEEPALIVE_INTERVAL = 26.625  # seconds
    HANDSHAKE_TIMEOUT = 5  # seconds
    MAX_KEEPALIVES = 5
    STATE_DISCONNECTED = 0
    STATE_CONNECTED = 1
    BUFFER = 1024

    def __init__(self, client_id, server_ip, server_port, key, logger=None):
        self.comms = EncryptedUDPComms(key, logger=logger)
        self.client_id = client_id
        self.server_ip = server_ip
        self.server_port = server_port
        self.state = self.STATE_DISCONNECTED
        self.next_timeout = time.monotonic()
        self.keepalive_count = 0
        self.handshake_id = int(time.time())

    def send_handshake(self):
        self.handshake_id += 1
        self.comms.sendmsg(
            {
                'id': self.client_id,
                'type': 'handshake_init',
                'data': [self.handshake_id, self.keepalive_count],
            },
            self.server_ip,
            self.server_port,
        )

    def send_keepalive(self):
        self.keepalive_count += 1
        self.comms.sendmsg(
            {
                'id': self.client_id,
                'type': 'keepalive',
                'data': [self.handshake_id, self.keepalive_count],
            },
            self.server_ip,
            self.server_port,
        )

    def do_receive(self):
        msg, _ = self.comms.recvmsg()
        if msg['data'][0] == self.handshake_id:
            self.state = self.STATE_CONNECTED
            self.next_timeout = time.monotonic()

    def do_timeout(self):
        if self.state == self.STATE_DISCONNECTED:
            self.send_handshake()
            self.next_timeout = time.monotonic() + self.HANDSHAKE_TIMEOUT
        elif self.state == self.STATE_CONNECTED:
            self.send_keepalive()
            if self.keepalive_count == self.MAX_KEEPALIVES:
                self.keepalive_count = 0
                self.state = self.STATE_DISCONNECTED
                self.next_timeout = time.monotonic()
            else:
                self.next_timeout = time.monotonic() + self.KEEPALIVE_INTERVAL
        else:
            raise ValueError(self.state)

    def run(self):
        while True:
            events = self.comms.poller.poll(
                1000 * max(0, self.next_timeout - time.monotonic())
            )
            if events:
                self.do_receive()
            else:
                self.do_timeout()


if __name__ == '__main__':
    import argparse
    from offlog import Logger

    parser = argparse.ArgumentParser(description='UDP connectivity monitor')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        '--client',
        action='store_true',
        help='run client',
    )
    mode_group.add_argument(
        '--server',
        action='store_true',
        help='run server',
    )
    mode_group.add_argument(
        '--generate-key',
        action='store_true',
        help='generate and output an encryption encryption/authentication key, and exit',
    )
    parser.add_argument(
        '--id',
        type=str,
        help='unique client id string',
        metavar='ID',
    )
    parser.add_argument(
        '--host',
        type=str,
        help='client: IPv4 address of server, server: bind address (server, default: 0.0.0.0)',
        metavar='HOST',
    )
    parser.add_argument(
        '--port',
        type=int,
        required=False,
        help=f'Server UDP port, default {Server.DEFAULT_PORT}',
        metavar='PORT',
    )
    parser.add_argument(
        '--key',
        type=str,
        help='16-byte, base64-encoded encryption/authentication key, as output by --generate-key',
        metavar='KEY',
    )
    parser.add_argument(
        '--log',
        type=str,
        help='log filepath (default: udp-canary.log)',
        metavar='LOG',
    )
    args = parser.parse_args()

    if args.generate_key:
        key = generate_key()
        print(key)
        sys.exit(0)

    if args.log is None:
        args.log = 'udp-canary.log'

    logger = Logger('udp-canary', filepath=args.log, local_file=True)

    if args.client:
        if args.id is None:
            parser.error('--id required')
        if args.host is None:
            parser.error('--host required')
    if args.server:
        if args.host is None:
            args.host = '0.0.0.0'
    if args.key is None:
        parser.error('--key required')
    if args.port is None:
        args.port = Server.DEFAULT_PORT
    try:
        if args.client:
            client = Client(
                args.id, args.host, args.port, args.key, logger=logger
            )
            client.run()
        else:
            server = Server(args.host, args.port, args.key, logger=logger)
            server.run()
    except KeyboardInterrupt:
        logger.info("Exit")
