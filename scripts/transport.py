"""Bounded JSON transport to one authenticated, stateful device endpoint."""
import json
import hashlib
import os
import select
import subprocess
import threading
import time
from stderr import BoundedStderr
from configuration import load_config
import activity
from redaction import redact_line
from contextvars import copy_context

MAX_REPLY = 262144
TRANSPORT_ERRORS = {'endpoint_reply_timeout', 'endpoint_write_timeout', 'endpoint_eof',
                    'endpoint_process_exited', 'endpoint_unavailable', 'endpoint_invalid_reply',
                    'endpoint_reply_too_large', 'endpoint_io_error'}
ENDPOINT_OPERATIONS = {'generate', 'validate', 'sign_remote', 'session_signed', 'step',
                       'token', 'confirm', 'setup', 'reset', 'get_state', 'drop', 'exit'}


class EndpointError(RuntimeError):
    def __init__(self, message, code=None, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def transport_details(error):
    """Select failure facts without copying messages, request data or stderr."""
    code = error.code
    details = error.details if isinstance(error.details, dict) else {}
    selected = {'code': code if isinstance(code, str) and code in TRANSPORT_ERRORS else 'endpoint_error'}
    for name in ('errno', 'exit_code', 'reply_bytes', 'request_bytes', 'written_bytes'):
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
    def __init__(self, config=None, *, command=None, timeout=None, expected_certificate_sha256=None):
        config = config or load_config()
        self.timeout = config.timeout if timeout is None else timeout
        self._buffer = bytearray()
        self._lock = threading.Lock()
        self._failed = False
        self.failure = None
        self._closing = False
        self._closed = False
        self._stderr = None
        self.process = None
        self.certificate_binding_verified = False
        try:
            arguments = activity.ssh_command(command or config.ssh_command())
            activity.emit('Endpoint', 'process starting', argv=arguments)
            self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            context = copy_context()
            callback = (lambda line: context.run(activity.emit, 'SSH stderr', redact_line(line), 'debug')) if activity.enabled() else None
            self._stderr = BoundedStderr(self.process.stderr, on_line=callback)
            self.ready = self.read()
            activity.emit('Endpoint', 'greeting', pid=self.process.pid, reply=self.ready)
            if self.ready.get('ready') is not True:
                from keystore import bridge_capabilities
                code = self.ready.get('error')
                if code not in ('required_keystore_symbols_unavailable', 'keystore_library_unavailable',
                                'device_certificate_unavailable', 'roothide_path_translation_unavailable'):
                    code = None
                raise EndpointError('Backend endpoint did not report ready', code,
                                    {'capabilities': bridge_capabilities(self.ready)})
            if self.ready.get('protocol_version', 1) != 1:
                raise EndpointError('Unsupported backend protocol version')
            fingerprint = self.ready.get('dcrt_sha256')
            if fingerprint is not None or expected_certificate_sha256 is not None:
                expected = expected_certificate_sha256
                if expected is None:
                    expected = hashlib.sha256(config.certificate_file.read_bytes()).hexdigest()
                if fingerprint != expected:
                    raise EndpointError('Local and backend device certificates do not match')
                self.certificate_binding_verified = True
        except BaseException as error:
            activity.emit('Endpoint', 'startup failed', 'error', error_type=type(error).__name__, error=str(error))
            self._failed = True
            self.close()
            raise

    def _error(self, message, code, **details):
        if self.process is not None:
            exit_code = self.process.poll()
            if exit_code is not None:
                details['exit_code'] = exit_code
        return EndpointError(message, code, details)

    def read(self, *, deadline=None):
        """Read one bounded line, including replies already buffered by a read."""
        if deadline is None:
            deadline = time.monotonic()+self.timeout
        while True:
            newline = self._buffer.find(b'\n')
            if newline >= 0:
                if newline > MAX_REPLY:
                    raise self._error('Backend reply exceeds the size limit',
                                      'endpoint_reply_too_large', reply_bytes=newline)
                raw = bytes(self._buffer[:newline])
                del self._buffer[:newline+1]
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeError) as error:
                    raise self._error('Backend returned invalid JSON',
                                      'endpoint_invalid_reply', reply_bytes=len(raw)) from error
                if not isinstance(result,dict):
                    raise self._error('Backend reply must be an object',
                                      'endpoint_invalid_reply', reply_bytes=len(raw))
                activity.emit('Endpoint', 'reply', reply=result)
                return result
            if len(self._buffer)>MAX_REPLY:
                raise self._error('Backend reply exceeds the size limit',
                                  'endpoint_reply_too_large', reply_bytes=len(self._buffer))
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise self._error('Backend reply timed out; restart the Mirroring session',
                                  'endpoint_reply_timeout', reply_bytes=len(self._buffer))
            readable,_,_ = select.select([self.process.stdout],[],[],remaining)
            if not readable:
                continue
            chunk = os.read(self.process.stdout.fileno(),65536)
            if not chunk:
                raise self._error('Backend connection closed; check SSH and the device jailbreak',
                                  'endpoint_eof', reply_bytes=len(self._buffer))
            self._buffer.extend(chunk)

    def call(self, operation, *, _deadline=None, **fields):
        with self._lock:
            if self._failed or (self._closing and operation != 'exit') or self.process is None:
                raise self._error('Backend session is unavailable; start a new session', 'endpoint_unavailable')
            if self.process.poll() is not None:
                error = self._error('Backend session is unavailable; start a new session', 'endpoint_process_exited')
                self.failure = self.failure or error
                raise error
            payload = (json.dumps({'operation':operation,**fields})+'\n').encode()
            activity.emit('Endpoint', 'request', operation=operation, parameters=fields, request_bytes=len(payload))
            if len(payload)>MAX_REPLY:
                raise ValueError('Backend request exceeds the size limit')
            stage = 'write'
            try:
                # A wedged endpoint must not suspend the session supervisor by
                # filling an SSH pipe. Bound both writes and partial replies.
                fd = self.process.stdin.fileno()
                os.set_blocking(fd,False)
                deadline = time.monotonic()+self.timeout
                if _deadline is not None:
                    deadline = min(deadline, _deadline)
                position = 0
                while position<len(payload):
                    remaining = deadline-time.monotonic()
                    if remaining<=0:
                        raise self._error('Backend request timed out', 'endpoint_write_timeout',
                                          request_bytes=len(payload), written_bytes=position)
                    _,writable,_ = select.select([],[fd],[],remaining)
                    if writable:
                        try:
                            position += os.write(fd,payload[position:])
                        except BlockingIOError:
                            continue
                stage = 'reply'
                return self.read(deadline=deadline)
            except (OSError,ValueError,EndpointError) as error:
                # A delayed reply can no longer be matched to a future request.
                # Replacing the connection would also lose all keybag state.
                self._failed = True
                if isinstance(error, EndpointError):
                    failure = EndpointError(str(error), error.code, dict(error.details))
                else:
                    details = {'stage': stage}
                    if isinstance(error, OSError) and type(error.errno) is int:
                        details['errno'] = error.errno
                    failure = self._error('Backend transport I/O failed; start a new session',
                                          'endpoint_io_error', **details)
                if isinstance(operation, str) and operation in ENDPOINT_OPERATIONS:
                    failure.details['operation'] = operation
                self.failure = self.failure or failure
                raise failure from error

    def close(self):
        if self._closed:
            return
        self._closing = True
        # A request already waiting on a stalled device must not prevent
        # shutdown from interrupting SSH and releasing the session controller.
        if self._lock.acquire(blocking=False):
            self._lock.release()
        else:
            self._failed = True
        self.timeout = min(self.timeout,2)
        if self.process is not None:
            if self.process.poll() is None:
                if not self._failed:
                    try:
                        self.call('exit')
                        self.process.wait(timeout=2)
                    except (EndpointError,subprocess.TimeoutExpired):
                        pass
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=3)
            for stream in (self.process.stdin,self.process.stdout):
                if stream:
                    stream.close()
        if self._stderr is not None:
            self._stderr.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()
