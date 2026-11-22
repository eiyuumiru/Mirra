"""Bounded JSON transport to one authenticated, stateful bridge session.

The session is one WebSocket on the phone's bridge service, carried by
TLS-PSK (see bridgeclient.py). Closing it releases every keybag and native
session the bridge created for it, so a new connection never inherits state.
"""
import hashlib
import json
import threading
import time
from configuration import load_config
import activity
from bridgeclient import BridgeClosed, BridgeError, BridgeTimeout, WebSocket, read_token, session_path

MAX_REPLY = 262144
PROTOCOL_VERSION = 2
TRANSPORT_ERRORS = {'endpoint_reply_timeout', 'endpoint_write_timeout', 'endpoint_eof',
                    'endpoint_disconnected', 'endpoint_unavailable', 'endpoint_invalid_reply',
                    'endpoint_reply_too_large', 'endpoint_io_error'}
ENDPOINT_OPERATIONS = {'generate', 'validate', 'sign_remote', 'session_signed', 'step',
                       'token', 'confirm', 'setup', 'reset', 'get_state', 'drop', 'exit', 'forget'}
GREETING_ERRORS = {'required_keystore_symbols_unavailable', 'keystore_library_unavailable',
                   'device_certificate_unavailable'}
CONNECTION_ERRORS = {'bridge_pairing_missing', 'bridge_tls_unavailable', 'bridge_unreachable',
                     'bridge_refused', 'bridge_token_rejected', 'bridge_session_limit'}


class EndpointError(RuntimeError):
    def __init__(self, message, code=None, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def transport_details(error):
    """Select failure facts without copying messages or request data."""
    code = error.code
    details = error.details if isinstance(error.details, dict) else {}
    selected = {'code': code if isinstance(code, str) and code in TRANSPORT_ERRORS else 'endpoint_error'}
    for name in ('reply_bytes', 'request_bytes'):
        value = details.get(name)
        if type(value) is int:
            selected[name] = value
    if details.get('stage') in ('write', 'reply'):
        selected['stage'] = details['stage']
    operation = details.get('operation')
    if isinstance(operation, str) and operation in ENDPOINT_OPERATIONS:
        selected['operation'] = operation
    return selected


class Endpoint:
    def __init__(self, config=None, *, timeout=None, expected_certificate_sha256=None, token=None, saved=False):
        """`saved` asks the bridge to keep this Mac's keys (the runtime broker only;
        setup and diagnostics use throwaway keys)."""
        config = config or load_config()
        self.timeout = config.timeout if timeout is None else timeout
        self._lock = threading.Lock()
        self._failed = False
        self.failure = None
        self._closing = False
        self._closed = False
        self.socket = None
        self.certificate_binding_verified = False
        try:
            token = token or read_token(config.token_file)
            activity.emit('Endpoint', 'connecting', transport=config.transport, port=config.service_port)
            try:
                self.socket = WebSocket.open(config, token, session_path(saved), timeout=self.timeout)
            except BridgeError as error:
                code = error.code if error.code in CONNECTION_ERRORS else 'endpoint_unavailable'
                raise EndpointError(str(error), code) from error
            self.ready = self.read()
            activity.emit('Endpoint', 'greeting', reply=self.ready)
            if self.ready.get('ready') is not True:
                from keystore import bridge_capabilities
                code = self.ready.get('error')
                raise EndpointError('Bridge service did not report ready',
                                    code if code in GREETING_ERRORS else None,
                                    {'capabilities': bridge_capabilities(self.ready)})
            if self.ready.get('protocol_version') != PROTOCOL_VERSION:
                raise EndpointError('Unsupported bridge protocol version; reinstall the bridge service')
            fingerprint = self.ready.get('dcrt_sha256')
            expected = expected_certificate_sha256
            if expected is None:
                expected = hashlib.sha256(config.certificate_file.read_bytes()).hexdigest()
            if fingerprint != expected:
                raise EndpointError('Local and bridge device certificates do not match')
            self.certificate_binding_verified = True
        except BaseException as error:
            activity.emit('Endpoint', 'startup failed', 'error', error_type=type(error).__name__, error=str(error))
            self._failed = True
            self.close()
            raise

    def _error(self, message, code, **details):
        return EndpointError(message, code, details)

    def read(self, *, deadline=None):
        """Read one bounded JSON object."""
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        try:
            raw = self.socket.receive(deadline)
        except BridgeTimeout as error:
            raise self._error('Bridge reply timed out; restart the Mirroring session',
                              'endpoint_reply_timeout') from error
        except BridgeClosed as error:
            raise self._error('Bridge connection closed; check the phone’s network and jailbreak',
                              'endpoint_eof') from error
        except BridgeError as error:
            code = 'endpoint_reply_too_large' if error.code == 'bridge_message_too_large' else 'endpoint_invalid_reply'
            raise self._error(str(error), code) from error
        if len(raw) > MAX_REPLY:
            raise self._error('Bridge reply exceeds the size limit', 'endpoint_reply_too_large', reply_bytes=len(raw))
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            raise self._error('Bridge returned invalid JSON', 'endpoint_invalid_reply', reply_bytes=len(raw)) from error
        if not isinstance(result, dict):
            raise self._error('Bridge reply must be an object', 'endpoint_invalid_reply', reply_bytes=len(raw))
        activity.emit('Endpoint', 'reply', reply=result)
        return result

    def poll(self):
        """None while the session is connected; 0 once the bridge has closed it."""
        if self.socket is None:
            return 0
        if not self._lock.acquire(blocking=False):
            return None  # A request is in flight; its own result reports failures.
        try:
            return 0 if self.socket.disconnected() else None
        finally:
            self._lock.release()

    def call(self, operation, *, _deadline=None, **fields):
        with self._lock:
            if self._failed or (self._closing and operation != 'exit') or self.socket is None:
                raise self._error('Bridge session is unavailable; start a new session', 'endpoint_unavailable')
            if self.socket.closed:
                error = self._error('Bridge session is unavailable; start a new session', 'endpoint_disconnected')
                self.failure = self.failure or error
                raise error
            payload = json.dumps({'operation': operation, **fields}).encode()
            activity.emit('Endpoint', 'request', operation=operation, parameters=fields, request_bytes=len(payload))
            if len(payload) > MAX_REPLY:
                raise ValueError('Bridge request exceeds the size limit')
            deadline = time.monotonic() + self.timeout
            if _deadline is not None:
                deadline = min(deadline, _deadline)
            stage = 'write'
            try:
                try:
                    self.socket.send_text(payload, deadline)
                except BridgeTimeout as error:
                    raise self._error('Bridge request timed out', 'endpoint_write_timeout',
                                      request_bytes=len(payload)) from error
                stage = 'reply'
                return self.read(deadline=deadline)
            except (OSError, ValueError, EndpointError) as error:
                # A delayed reply can no longer be matched to a future request.
                # Replacing the connection would also lose all keybag state.
                self._failed = True
                if isinstance(error, EndpointError):
                    failure = EndpointError(str(error), error.code, dict(error.details))
                else:
                    failure = self._error('Bridge transport I/O failed; start a new session',
                                          'endpoint_io_error', stage=stage)
                if isinstance(operation, str) and operation in ENDPOINT_OPERATIONS:
                    failure.details['operation'] = operation
                self.failure = self.failure or failure
                raise failure from error

    def close(self):
        if self._closed:
            return
        self._closing = True
        # A request already waiting on a stalled bridge must not prevent
        # shutdown from closing the connection and releasing the controller.
        if self._lock.acquire(blocking=False):
            self._lock.release()
        else:
            self._failed = True
        self.timeout = min(self.timeout, 2)
        if self.socket is not None:
            if not self._failed and not self.socket.closed:
                try:
                    self.call('exit')
                except EndpointError:
                    pass
            self.socket.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
