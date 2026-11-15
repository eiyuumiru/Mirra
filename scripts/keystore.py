"""Own backend identities and translate only this broker's session handles."""
import base64
import re
import time

from transport import EndpointError, transport_details
from wire import platform_ltk

SESSION_BASE = 0x6F000000
SESSION_END = 0x70000000
MAX_SESSIONS = 16  # The endpoint's isolated-session limit.
MAX_RESET_SECONDS = 10  # Leave room inside the shim's 15-second socket timeout.
NO_MEMORY = -536870211  # kIOReturnNoMemory (0xe00002bd)
UNAVAIWORKSPACELE = -536870212  # kIOReturnError (0xe00002bc)


def bridge_capabilities(report):
    """Select hardware/API observations without certificates or device identities."""
    selected = {}
    patterns = {'product_type': r'iPhone\d+,\d+', 'os_version': r'\d+(?:\.\d+){1,2}',
                'os_build': r'\d+[A-Z]\d+[a-z]?', 'minimum_ios': r'\d+(?:\.\d+){1,2}'}
    for name, pattern in patterns.items():
        value = report.get(name)
        if isinstance(value, str) and len(value) <= 32 and re.fullmatch(pattern, value):
            selected[name] = value
    if report.get('process_architecture') in ('arm64', 'arm64e', 'x86_64'):
        selected['process_architecture'] = report['process_architecture']
    missing = report.get('missing_symbols')
    if isinstance(missing, list) and len(missing) <= 18 and all(
            isinstance(value, str) and re.fullmatch(r'aks_[a-z0-9_]{1,64}', value) for value in missing):
        selected['missing_symbols'] = missing
    return selected


def operation_details(report):
    """Preserve native status and stage; never copy an identity or key blob."""
    selected = {}
    if type(report.get('status')) is int:
        selected['status'] = report['status']
        selected['status_hex'] = f"0x{report['status'] & 0xffffffff:08x}"
    stage = report.get('operation_stage')
    if stage in ('SecRandomCopyBytes', 'aks_create_bag', 'aks_create_signing_key',
                 'aks_params_create', 'aks_params_set_data', 'aks_params_set_number',
                 'aks_params_get_der', 'aks_create_signing_key_with_params', 'aks_validate_local_key'):
        selected['operation_stage'] = stage
    return selected


def valid_generated_key(report):
    return (type(report.get('status')) is int and report['status'] == 0 and not report.get('error')
            and isinstance(report.get('identity'), str) and bool(report['identity'])
            and isinstance(report.get('ltk'), str) and bool(report['ltk']))


def verify_attested_key(endpoint):
    """Validate one isolated key with the same checks during setup and diagnosis."""
    capabilities = bridge_capabilities(endpoint.ready)
    generated = endpoint.call('generate', attested=True, key_class=9)
    if not valid_generated_key(generated):
        details = {'operation': 'generate', 'capabilities': capabilities, **operation_details(generated)}
        raise EndpointError('The bridge cannot create the required attested key',
                            'bridge_attested_key_unavailable', details)
    validated = endpoint.call('validate', identity=generated['identity'])
    if type(validated.get('status')) is not int or validated['status'] != 0 or validated.get('error'):
        details = {'operation': 'validate', 'capabilities': capabilities, **operation_details(validated)}
        raise EndpointError('The bridge rejected its fresh attested key',
                            'bridge_attested_key_rejected', details)
    try:
        _, proof = platform_ltk(generated['ltk'], 3)
    except ValueError as error:
        raise EndpointError(str(error), 'bridge_key_layout_unsupported',
                            {'operation': 'wire_layout', 'capabilities': capabilities}) from error
    return proof


class AksBroker:
    """Calls are serialized by the socket server, including health and cleanup."""
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.identities = {}
        self.classes = {}
        self.sessions = {}
        self.counter = 0
        self.wire_keys = {}
        self.failure = None
        self.transport_failure = None

    def reset_owned_sessions(self):
        # One client request, one overall endpoint timeout, at most 16 actual
        # handles. Never guess handles or reset the phone's system keybags.
        deadline = time.monotonic() + min(self.endpoint.timeout, MAX_RESET_SECONDS)
        first_error = 0
        count = 0
        for virtual, real in list(self.sessions.items()):
            try:
                response = self.endpoint.call('reset', session=real, data='', _deadline=deadline)
            except EndpointError as error:
                self.failure = self.failure or 'owned_session_reset_transport_failed'
                self.transport_failure = self.transport_failure or transport_details(error)
                return {'status': UNAVAIWORKSPACELE, 'error': 'owned_session_reset_transport_failed',
                        'reset_count': count, 'remaining_sessions': len(self.sessions),
                        'transport_failure': self.transport_failure}
            status = response.get('status', UNAVAIWORKSPACELE)
            if type(status) is not int:
                status = UNAVAIWORKSPACELE
            if status == 0:
                self.sessions.pop(virtual)
                count += 1
            elif not first_error:
                first_error = status
        if first_error:
            self.failure = self.failure or 'owned_session_reset_failed'
        return {'status': first_error, 'reset_count': count, 'remaining_sessions': len(self.sessions)}

    def execute(self, request):
        operation = request.get('operation')
        if operation == 'health':
            first_error = getattr(self.endpoint, 'failure', None)
            if isinstance(first_error, EndpointError):
                self.failure = self.failure or 'endpoint_transport_failed'
                self.transport_failure = self.transport_failure or transport_details(first_error)
            exit_code = self.endpoint.process.poll()
            if exit_code is not None:
                self.failure = self.failure or 'endpoint_exited'
                self.transport_failure = self.transport_failure or {
                    'code': 'endpoint_process_exited', 'exit_code': exit_code}
            alive = self.failure is None
            if alive and self.classes:
                identity = next(iter(self.classes.values()))['identity']
                try:
                    status = self.endpoint.call('validate', identity=identity).get('status')
                    if type(status) is not int or status != 0:
                        self.failure = 'identity_validation_failed'
                except EndpointError as error:
                    # The transport has abandoned this command stream. Report a
                    # confirmed failure, instead of dropping the health reply.
                    self.failure = 'endpoint_transport_failed'
                    self.transport_failure = transport_details(error)
                alive = self.failure is None
            response = {'ready': alive, 'identities': len(self.identities), 'sessions': len(self.sessions),
                        'capabilities': ['reset_owned_sessions']}
            if self.failure:
                response['error'] = self.failure
            if self.transport_failure:
                response['transport_failure'] = self.transport_failure
            return response
        if operation == 'reset_owned_sessions':
            return self.reset_owned_sessions()
        if self.failure:
            return {'status': UNAVAIWORKSPACELE, 'error': 'broker_requires_restart'}
        if operation == 'generate':
            key_class = request.get('key_class', 9)
            if type(key_class) is not int or key_class not in (9, 10, 11):
                return {'error': 'invalid_key_class'}
            if key_class not in self.classes:
                response = self.endpoint.call('generate', attested=True, key_class=key_class)
                if type(response.get('status')) is int and response['status'] != 0:
                    return response
                if not valid_generated_key(response):
                    self.failure = 'invalid_signing_key_result'
                    return {'status': UNAVAIWORKSPACELE, 'error': self.failure,
                            'backend_operation': operation_details(response)}
                try:
                    wire, _proof = platform_ltk(response['ltk'], 3)
                except ValueError:
                    self.failure = 'unsupported_signing_key_layout'
                    return {'status': UNAVAIWORKSPACELE, 'error': self.failure,
                            'backend_operation': operation_details(response)}
                self.wire_keys[key_class] = wire
                self.identities[wire] = response['identity']
                self.classes[key_class] = response
                self.identities[response['ltk']] = response['identity']
            response = self.classes[key_class]
            wire = self.wire_keys[key_class]
            return {'status': 0, 'data': wire, 'bytes': len(base64.b64decode(wire))}
        if operation in {'validate', 'sign_remote', 'session_signed'}:
            identity = self.identities.get(request.get('local_ltk'))
            if identity is None:
                return {'error': 'local_key_not_owned'}
            if operation == 'session_signed':
                if self.counter >= SESSION_END - SESSION_BASE - 1:
                    return {'status': UNAVAIWORKSPACELE, 'error': 'session_namespace_exhausted'}
                if len(self.sessions) >= MAX_SESSIONS:
                    return {'status': NO_MEMORY, 'error': 'owned_session_limit'}
            fields = {'identity': identity}
            if operation != 'validate':
                fields.update(remote_ltk=request.get('remote_ltk', ''),
                              remote_key_class=request.get('remote_key_class', 9),
                              flags=request.get('flags', 0), parameters=request.get('parameters', ''))
            response = dict(self.endpoint.call(operation, **fields))
            if operation == 'session_signed' and response.get('status') == 0:
                real = response.get('session')
                if type(real) is not int or real < 0 or real in self.sessions.values():
                    self.failure = 'invalid_session_handle'
                    raise EndpointError('Backend returned an invalid or duplicate session handle')
                self.counter += 1
                virtual = SESSION_BASE + self.counter
                self.sessions[virtual] = real
                response['session'] = virtual
            return response
        if operation in {'step', 'token', 'confirm', 'setup', 'reset'}:
            virtual = request.get('session')
            if type(virtual) is not int or virtual not in self.sessions:
                return {'error': 'session_not_owned'}
            response = self.endpoint.call(operation, session=self.sessions[virtual], data=request.get('data', ''))
            if operation == 'reset' and response.get('status') == 0:
                self.sessions.pop(virtual)
            return response
        if operation in {'get_state', 'drop'}:
            return self.endpoint.call(operation, data=request.get('data', ''))
        return {'error': 'unknown_operation'}
