"""An isolated WebSocket peer for the Python endpoint regressions.

The production frame reader/writer use a real socket pair. TLS authentication
and HTTP upgrade are covered separately by the native endpoint checks.
"""
import hashlib
import json
import socket
import struct
import threading
from types import SimpleNamespace
from unittest.mock import patch

from bridgeclient import WebSocket
from transport import Endpoint

CERTIFICATE_SHA256 = hashlib.sha256(b'fixture certificate').hexdigest()
GREETING = {'ready': True, 'protocol_version': 2, 'dcrt_sha256': CERTIFICATE_SHA256}
TOKEN = 'A' * 24


def frame(payload, opcode=1):
    if len(payload) < 126:
        head = struct.pack('!BB', 0x80 | opcode, len(payload))
    elif len(payload) <= 0xffff:
        head = struct.pack('!BBH', 0x80 | opcode, 126, len(payload))
    else:
        head = struct.pack('!BBQ', 0x80 | opcode, 127, len(payload))
    return head + payload


class BridgeFixture:
    def __init__(self, handler=None, *, greeting=None, timeout=1, initial=(), before_requests=None):
        self.handler = handler or (lambda request, peer: {'status': 0})
        self.greeting = GREETING if greeting is None else greeting
        self.timeout = timeout
        self.initial = initial
        self.before_requests = before_requests
        self.client, self.stream = socket.socketpair()
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.stream.settimeout(5)
        self.websocket = WebSocket(self.client)
        self.endpoint = None
        self.requests = []
        self.errors = []
        self.stop = threading.Event()
        self.request_received = threading.Event()
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def connect(self, config=None, **kwargs):
        config = config or SimpleNamespace(timeout=self.timeout, transport='ssh', service_port=47820)
        options = {'timeout': self.timeout, 'expected_certificate_sha256': CERTIFICATE_SHA256, 'token': TOKEN}
        options.update(kwargs)
        with patch('transport.WebSocket.open', return_value=self.websocket):
            self.endpoint = Endpoint(config, **options)
        return self.endpoint

    def send_text(self, payload):
        self.stream.sendall(frame(payload))

    def send_json(self, value):
        self.send_text(json.dumps(value).encode())

    def readn(self, count):
        data = bytearray()
        while len(data) < count:
            chunk = self.stream.recv(count - len(data))
            if not chunk:
                raise EOFError()
            data.extend(chunk)
        return bytes(data)

    def receive(self):
        first, second = self.readn(2)
        if first & 0x70 or not first & 0x80 or not second & 0x80:
            raise AssertionError('Client sent an invalid or unmasked frame')
        size = second & 0x7f
        if size == 126:
            size = struct.unpack('!H', self.readn(2))[0]
        elif size == 127:
            size = struct.unpack('!Q', self.readn(8))[0]
        mask = self.readn(4)
        payload = bytes(value ^ mask[index & 3] for index, value in enumerate(self.readn(size)))
        if first & 0x0f == 8:
            return None
        if first & 0x0f != 1:
            raise AssertionError('Client sent an unexpected opcode')
        request = json.loads(payload)
        if not isinstance(request, dict):
            raise AssertionError('Client request is not an object')
        return request

    def serve(self):
        try:
            self.stream.sendall(b''.join(frame(json.dumps(value).encode())
                                        for value in (self.greeting, *self.initial)))
            if self.before_requests:
                self.before_requests(self)
            while not self.stop.is_set():
                request = self.receive()
                if request is None:
                    break
                self.requests.append(request)
                self.request_received.set()
                reply = self.handler(request, self)
                if isinstance(reply, bytes):
                    self.send_text(reply)
                elif reply is not None:
                    self.send_json(reply)
                if request['operation'] == 'exit':
                    break
        except (EOFError, OSError):
            pass  # Closing a timed-out endpoint interrupts its peer as well.
        except BaseException as error:
            self.errors.append(error)
        finally:
            self.closed.set()
            self.stream.close()

    def __exit__(self, *_):
        self.stop.set()
        if self.endpoint is not None:
            self.endpoint.close()
        else:
            self.websocket.close()
        try:
            self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.thread.join(2)
        self.stream.close()
        if self.thread.is_alive():
            raise AssertionError('Fixture peer did not stop')
        if self.errors:
            raise self.errors[0]
