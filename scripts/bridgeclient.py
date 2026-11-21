"""TLS-PSK HTTP and WebSocket client for the bridge service on the phone.

SSH is used only to install the service. Afterwards the Mac connects to one
TCP port on the phone (over Wi-Fi, or through usbmux over USB). TLS 1.2
ECDHE-PSK with ChaCha20-Poly1305 both encrypts the connection and proves that
each side holds the pairing token: the pre-shared key is derived from it, so a
peer without the token cannot finish the handshake. No certificate is involved.
"""
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse

DEFAULT_PORT = 47820
BRIDGE_REVISION = 1
TOKEN_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
TOKEN_LENGTH = 24
PSK_IDENTITY = 'mirra-bridge-v1'
PSK_CONTEXT = b'mirra-bridge-psk-v1\x00'
CIPHER = 'ECDHE-PSK-CHACHA20-POLY1305'
WEBSOCKET_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
MAX_MESSAGE = 262144
MAX_HEADER = 16384
MAX_BODY = 1048576 + 65536


class BridgeError(OSError):
    """A connection-level failure with a stable code for diagnostics."""
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


class BridgeTimeout(BridgeError):
    def __init__(self, message='Bridge did not answer in time'):
        super().__init__(message, 'bridge_timeout')


class BridgeClosed(BridgeError):
    def __init__(self, message='Bridge closed the connection'):
        super().__init__(message, 'bridge_closed')


def normalize_token(value):
    """Return the 24-symbol token; accepts case, hyphens/spaces and O/I/L typos."""
    if not isinstance(value, str):
        raise ValueError('The pairing token must be text')
    token = ''.join(value.split()).replace('-', '').upper().replace('O', '0').replace('I', '1').replace('L', '1')
    if len(token) != TOKEN_LENGTH or any(c not in TOKEN_ALPHABET for c in token):
        raise ValueError('The pairing token must contain 24 letters or digits, as shown in the phone’s Settings')
    return token


def display_token(token):
    token = normalize_token(token)
    return '-'.join(token[i:i + 4] for i in range(0, TOKEN_LENGTH, 4))


def pre_shared_key(token):
    return hashlib.sha256(PSK_CONTEXT + normalize_token(token).encode()).digest()


def read_token(path):
    try:
        return normalize_token(path.read_text())
    except OSError as error:
        raise BridgeError('Missing bridge pairing token; run setup again or pair with the token from the phone’s Settings',
                          'bridge_pairing_missing') from error
    except ValueError as error:
        raise BridgeError('The saved bridge pairing token is invalid; pair again', 'bridge_pairing_missing') from error


def tls_context(token):
    if not hasattr(ssl.SSLContext, 'set_psk_client_callback'):
        raise BridgeError('This Python lacks TLS-PSK support; use Mirra’s bundled Python runtime',
                          'bridge_tls_unavailable')
    key = pre_shared_key(token)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Authentication comes from the pre-shared key, not from a certificate:
    # a server without the token cannot complete the PSK handshake.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.set_ciphers(CIPHER)
    except ssl.SSLError as error:
        raise BridgeError('This Python’s TLS library lacks ' + CIPHER, 'bridge_tls_unavailable') from error
    context.set_psk_client_callback(lambda hint: (PSK_IDENTITY, key))
    return context


_CLIENT = None


def client_identity():
    """This Mac's hardware UUID and name. The bridge saves this Mac's keys under
    the UUID and shows the name in the phone's Settings."""
    global _CLIENT
    if _CLIENT is None:
        uuid, name = '', ''
        try:
            report = subprocess.run(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                                    capture_output=True, text=True, timeout=5).stdout
            found = re.search(r'"IOPlatformUUID" = "([0-9A-Fa-f-]{36})"', report)
            uuid = found.group(1).upper() if found else ''
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            name = subprocess.run(['/usr/sbin/scutil', '--get', 'ComputerName'],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        name = ''.join(c for c in (name or socket.gethostname() or 'Mac') if c.isprintable())[:64]
        _CLIENT = (uuid, name or 'Mac')
    return _CLIENT


def session_path(saved=False):
    """A saved session keeps this Mac's keys on the bridge across restarts."""
    uuid, name = client_identity() if saved else ('', '')
    if not uuid:
        return '/v1/session'
    return '/v1/session?' + urllib.parse.urlencode({'client': uuid, 'name': name})


def destination(config):
    return ('usb', config.serial or config.product_type) if config.transport == 'usb' else (config.ssh_host, config.service_port)


def open_socket(config, token, timeout):
    """Open one authenticated, encrypted stream to the bridge service."""
    context = tls_context(token)
    try:
        if config.transport == 'usb':
            from usbmux import connect, list_devices, select_device
            device = select_device(list_devices(), product=config.product_type, serial=config.serial)['DeviceID']
            raw = connect(device, config.service_port)
        else:
            raw = socket.create_connection((config.ssh_host, config.service_port), timeout=timeout)
    except socket.timeout as error:
        raise BridgeError('The bridge service did not answer; check the phone’s address and jailbreak', 'bridge_unreachable') from error
    except (OSError, ConnectionError, ValueError) as error:
        code = 'bridge_refused' if isinstance(error, ConnectionRefusedError) else 'bridge_unreachable'
        raise BridgeError('Cannot reach the bridge service: ' + str(error), code) from error
    raw.settimeout(timeout)
    try:
        stream = context.wrap_socket(raw, server_hostname=None, do_handshake_on_connect=False)
        stream.do_handshake()
        return stream
    except socket.timeout as error:
        raw.close()
        raise BridgeError('The bridge did not finish the secure handshake', 'bridge_unreachable') from error
    except ssl.SSLError as error:
        raw.close()
        raise BridgeError('The bridge rejected the pairing token. Pair again with the token shown in the phone’s Settings',
                          'bridge_token_rejected') from error
    except OSError as error:
        raw.close()
        raise BridgeError('The bridge closed the secure handshake: ' + str(error), 'bridge_unreachable') from error


def _receive(stream, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BridgeTimeout()
    stream.settimeout(remaining)
    try:
        return stream.recv(65536)
    except socket.timeout as error:
        raise BridgeTimeout() from error
    except ssl.SSLZeroReturnError:
        return b''


def _send(stream, data, deadline):
    view = memoryview(data)
    while view:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeTimeout('Bridge did not accept the request in time')
        stream.settimeout(remaining)
        try:
            count = stream.send(view)
        except socket.timeout as error:
            raise BridgeTimeout('Bridge did not accept the request in time') from error
        view = view[count:]


def _read_head(stream, buffer, deadline):
    while b'\r\n\r\n' not in buffer:
        if len(buffer) > MAX_HEADER:
            raise BridgeError('Bridge response headers are too large', 'bridge_protocol_error')
        chunk = _receive(stream, deadline)
        if not chunk:
            raise BridgeClosed('Bridge closed the connection before replying')
        buffer.extend(chunk)
    end = buffer.index(b'\r\n\r\n')
    lines = bytes(buffer[:end]).decode('latin-1').split('\r\n')
    del buffer[:end + 4]
    parts = lines[0].split(' ', 2)
    if len(parts) < 2 or parts[0] != 'HTTP/1.1' or not parts[1].isdigit():
        raise BridgeError('Bridge returned an invalid HTTP response', 'bridge_protocol_error')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        if not separator:
            raise BridgeError('Bridge returned an invalid HTTP header', 'bridge_protocol_error')
        headers[name.strip().lower()] = value.strip()
    return int(parts[1]), headers


def request(config, token, method, path, payload=None, *, timeout=None):
    """Send one HTTP request and return (status, content type, body)."""
    timeout = config.timeout if timeout is None else timeout
    deadline = time.monotonic() + timeout
    body = b'' if payload is None else json.dumps(payload).encode()
    head = (f'{method} {path} HTTP/1.1\r\nHost: mirra-bridge\r\nConnection: close\r\n'
            f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n').encode()
    stream = open_socket(config, token, timeout)
    try:
        _send(stream, head + body, deadline)
        buffer = bytearray()
        status, headers = _read_head(stream, buffer, deadline)
        length = headers.get('content-length', '')
        if not length.isdigit() or int(length) > MAX_BODY:
            raise BridgeError('Bridge response has an invalid length', 'bridge_protocol_error')
        while len(buffer) < int(length):
            chunk = _receive(stream, deadline)
            if not chunk:
                raise BridgeClosed('Bridge closed the connection during its reply')
            buffer.extend(chunk)
        return status, headers.get('content-type', ''), bytes(buffer[:int(length)])
    finally:
        stream.close()


def request_json(config, token, method, path, payload=None, *, timeout=None):
    status, content_type, body = request(config, token, method, path, payload, timeout=timeout)
    try:
        value = json.loads(body)
    except ValueError as error:
        raise BridgeError('Bridge returned invalid JSON', 'bridge_protocol_error') from error
    if not isinstance(value, dict):
        raise BridgeError('Bridge reply must be an object', 'bridge_protocol_error')
    return status, value


def bridge_revision(status):
    """Return an advertised revision, including known legacy bridges."""
    if status.get('service') != 'mirra-bridge' or status.get('protocol_version') != 2:
        return None
    revision = status.get('bridge_revision', 0)
    return revision if type(revision) is int and revision >= 0 else None


def has_ssh_access(config):
    return all(path.is_file() for path in (config.user_file, config.identity_file, config.known_hosts_file))


class WebSocket:
    """Client side of RFC 6455 for one keystore session (text frames only)."""
    def __init__(self, stream, buffer=b''):
        self.stream = stream
        self.buffer = bytearray(buffer)
        self.closed = False

    @classmethod
    def open(cls, config, token, path, *, timeout):
        deadline = time.monotonic() + timeout
        stream = open_socket(config, token, timeout)
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            _send(stream, (f'GET {path} HTTP/1.1\r\nHost: mirra-bridge\r\nUpgrade: websocket\r\n'
                           f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode(),
                  deadline)
            buffer = bytearray()
            status, headers = _read_head(stream, buffer, deadline)
            if status != 101:
                code = 'bridge_session_limit' if status == 503 else 'bridge_protocol_error'
                raise BridgeError(f'Bridge refused the session (HTTP {status})', code)
            expected = base64.b64encode(hashlib.sha1(key.encode() + WEBSOCKET_GUID).digest()).decode()
            if headers.get('sec-websocket-accept') != expected or headers.get('upgrade', '').lower() != 'websocket':
                raise BridgeError('Bridge returned an invalid WebSocket handshake', 'bridge_protocol_error')
            return cls(stream, buffer)
        except BaseException:
            stream.close()
            raise

    def _frame(self, opcode, payload):
        mask = os.urandom(4)
        size = len(payload)
        if size < 126:
            head = struct.pack('!BB', 0x80 | opcode, 0x80 | size)
        elif size <= 0xffff:
            head = struct.pack('!BBH', 0x80 | opcode, 0x80 | 126, size)
        else:
            head = struct.pack('!BBQ', 0x80 | opcode, 0x80 | 127, size)
        return head + mask + bytes(value ^ mask[index & 3] for index, value in enumerate(payload))

    def send_text(self, payload, deadline):
        if self.closed:
            raise BridgeClosed()
        _send(self.stream, self._frame(0x1, payload), deadline)

    def _parse(self):
        """Return (opcode, payload) for one complete frame, or None."""
        if len(self.buffer) < 2:
            return None
        first, second = self.buffer[0], self.buffer[1]
        if first & 0x70 or second & 0x80 or not first & 0x80:
            raise BridgeError('Bridge sent an invalid WebSocket frame', 'bridge_protocol_error')
        length, header = second & 0x7f, 2
        if length == 126:
            if len(self.buffer) < 4:
                return None
            length, header = struct.unpack('!H', self.buffer[2:4])[0], 4
        elif length == 127:
            if len(self.buffer) < 10:
                return None
            length, header = struct.unpack('!Q', self.buffer[2:10])[0], 10
        if length > MAX_MESSAGE:
            raise BridgeError('Bridge message exceeds the size limit', 'bridge_message_too_large')
        if len(self.buffer) < header + length:
            return None
        payload = bytes(self.buffer[header:header + length])
        del self.buffer[:header + length]
        return first & 0x0f, payload

    def _handle(self, frame, deadline):
        opcode, payload = frame
        if opcode == 0x8:
            self.closed = True
            raise BridgeClosed()
        if opcode == 0x9:
            _send(self.stream, self._frame(0xA, payload), deadline)
            return None
        if opcode == 0xA:
            return None
        if opcode != 0x1:
            raise BridgeError('Bridge sent an unsupported WebSocket frame', 'bridge_protocol_error')
        return payload

    def receive(self, deadline):
        while True:
            frame = self._parse()
            if frame is not None:
                payload = self._handle(frame, deadline)
                if payload is not None:
                    return payload
                continue
            chunk = _receive(self.stream, deadline)
            if not chunk:
                self.closed = True
                raise BridgeClosed()
            self.buffer.extend(chunk)

    def disconnected(self):
        """Non-blocking check, valid only between requests: the service never
        sends unsolicited data frames, so readable input means a closure."""
        if self.closed:
            return True
        try:
            self.stream.settimeout(0)
            chunk = self.stream.recv(65536)
        except (ssl.SSLWantReadError, BlockingIOError, socket.timeout):
            return False
        except ssl.SSLZeroReturnError:
            chunk = b''
        except OSError:
            self.closed = True
            return True
        if not chunk:
            self.closed = True
            return True
        self.buffer.extend(chunk)
        try:
            while (frame := self._parse()) is not None:
                if self._handle(frame, time.monotonic() + 1) is not None:
                    raise BridgeError('Bridge sent an unexpected message', 'bridge_protocol_error')
        except BridgeError:
            self.closed = True
            return True
        return False

    def close(self, deadline=None):
        if not self.closed:
            self.closed = True
            try:
                _send(self.stream, self._frame(0x8, struct.pack('!H', 1000)), deadline or time.monotonic() + 1)
            except OSError:
                pass
        try:
            self.stream.close()
        except OSError:
            pass
