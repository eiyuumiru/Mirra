"""Exercise the actual endpoint with isolated native APIs; no phone is accessed."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from keystore import AksBroker, MAX_SESSIONS, verify_attested_key
from transport import Endpoint, EndpointError
from bridgeclient import BridgeClosed, BridgeError, WebSocket, request, request_json
from wire import wrap

BINARY = ROOT / 'build/endpoint-protocol'
SCENARIOS = []
PROFILE = {'MODEL': 'iPhone11,2', 'IOS': '17.2', 'BUILD': '21C62'}
REMOTE = base64.b64encode(b'SYNTHETIC-REMOTE-KEY').decode()
TOKEN = 'K7QM-2XRA-9DFT-HW3N-PC6E-ZZ8B'
SYMBOLS = ('aks_create_bag', 'aks_unload_bag', 'aks_create_signing_key',
    'aks_create_signing_key_with_params', 'aks_sign_signing_key', 'aks_params_create',
    'aks_params_set_data', 'aks_params_set_number', 'aks_params_get_der',
    'aks_remote_session', 'aks_remote_session_step', 'aks_remote_session_reset',
    'aks_remote_session_token', 'aks_remote_peer_confirm', 'aks_remote_peer_setup',
    'aks_validate_local_key', 'aks_remote_peer_get_state', 'aks_remote_peer_drop')


def fixture_ltk():
    return wrap(0x30, b''.join(wrap(tag, bytes([tag]) * 100)
        for tag in (0x81, 0x85, 0x86, 0x82, 0x83, 0x84)))


class EndpointProtocolTests(unittest.TestCase):
    @contextmanager
    def native(self, **settings):
        with tempfile.TemporaryDirectory(prefix='mirra-endpoint-simulation-') as temporary:
            directory = Path(temporary)
            certificate = directory / 'certificate'; certificate.write_bytes(b'SYNTHETIC-CERTIFICATE')
            key = directory / 'key'; key.write_bytes(fixture_ltk())
            stats = directory / 'stats.json'
            environment = {name: value for name, value in os.environ.items() if not name.startswith('MIRRA_SIM_')}
            environment.update({'MIRRA_SIM_KEY_FILE': str(key), 'MIRRA_SIM_STATS_FILE': str(stats)})
            environment.update({'MIRRA_SIM_' + name: value for name, value in PROFILE.items()})
            environment.update({'MIRRA_SIM_' + name: str(value) for name, value in settings.items()})
            run = SimpleNamespace(directory=directory, certificate=certificate, stats={}, env=environment)
            with patch.dict(os.environ, environment, clear=True):
                try:
                    yield run
                finally:
                    if stats.is_file():
                        run.stats.update(json.loads(stats.read_text()))

    @contextmanager
    def service(self, run, *, certificate=True, token=TOKEN):
        """Run the real bridge service on a loopback port with synthetic native APIs."""
        directory = run.directory / 'service'
        directory.mkdir(mode=0o700)
        if certificate:
            (directory / 'certificate.der').write_bytes(run.certificate.read_bytes())
        (directory / 'token').write_text(TOKEN + '\n')
        process = subprocess.Popen([str(BINARY), '--serve', str(directory), '--port', '0'], env=run.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            started = json.loads(process.stdout.readline())
            self.assertTrue(started['listening'], started)
            run.service_directory = directory
            run.config = SimpleNamespace(transport='ssh', ssh_host='127.0.0.1', service_port=started['port'],
                                         timeout=3, certificate_file=run.certificate, token_file=directory / 'token')
            run.token = token
            yield run
        finally:
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), 0)
            process.stdout.close()

    @contextmanager
    def endpoint(self, **settings):
        with self.native(**settings) as run, self.service(run):
            with Endpoint(run.config, expected_certificate_sha256=hashlib.sha256(run.certificate.read_bytes()).hexdigest()) as endpoint:
                for field, setting in (('product_type', 'MODEL'), ('os_version', 'IOS'), ('os_build', 'BUILD')):
                    self.assertEqual(endpoint.ready[field], str(settings.get(setting, PROFILE[setting])))
                run.endpoint = endpoint
                yield run

    def generate(self, endpoint):
        result = endpoint.call('generate', attested=True, key_class=9)
        self.assertEqual(result['status'], 0)
        self.assertIn('identity', result)
        return result['identity']

    def session(self, endpoint, identity):
        return endpoint.call('session', identity=identity, remote_ltk=REMOTE)

    def record(self, name):
        SCENARIOS.append(name)

    def test_missing_required_symbols_fail_before_any_native_operation(self):
        for symbol in (*SYMBOLS, 'library'):
            with self.subTest(symbol=symbol), self.native(MISSING=symbol) as run:
                reply = subprocess.run([str(BINARY), '--capabilities'], env=run.env,
                                       capture_output=True, timeout=3)
                value = json.loads(reply.stdout)
                self.assertEqual(reply.returncode, 1)
                self.assertFalse(value['required_symbols_available'])
                self.assertEqual(value['missing_symbols'], list(SYMBOLS) if symbol == 'library' else [symbol])
                self.assertFalse(value['end_to_end_verified'])
            self.assertEqual(run.stats['calls'], {})
            self.record('missing:' + symbol)

    def test_successful_broker_lifecycle_for_all_supported_key_classes(self):
        with self.endpoint() as run:
            endpoint = run.endpoint
            proof = verify_attested_key(endpoint)
            self.assertTrue(proof['original_fields_byte_identical'])
            self.assertFalse(proof['stock_phone_acceptance_verified'])
            broker = AksBroker(endpoint)
            for key_class in (9, 10, 11):
                local = broker.execute({'operation': 'generate', 'key_class': key_class})
                signed = broker.execute({'operation': 'sign_remote', 'local_ltk': local['data'], 'remote_ltk': REMOTE})
                self.assertEqual(signed['status'], 0)
                session = broker.execute({'operation': 'session_signed', 'local_ltk': local['data'], 'remote_ltk': signed['data']})
                self.assertEqual(session['status'], 0)
                for operation in ('token', 'step', 'setup', 'confirm'):
                    result = broker.execute({'operation': operation, 'session': session['session'], 'data': REMOTE})
                    self.assertEqual(result['status'], 0)
                    self.assertEqual(base64.b64decode(result['data']), b'SYNTHETIC')
                self.assertEqual(broker.execute({'operation': 'get_state', 'data': signed['data']})['bytes'], 104)
                self.assertEqual(broker.execute({'operation': 'drop', 'data': signed['data']})['status'], 0)
                self.assertEqual(broker.execute({'operation': 'reset', 'session': session['session']})['status'], 0)
                self.record('full_synthetic_lifecycle:key_class=' + str(key_class))
        self.assertEqual(len(run.stats['unloads']), 4)
        self.assertEqual(len(run.stats['resets']), 3)

    def test_generation_stops_at_every_failed_intermediate_api_and_cleans_up(self):
        stages = ('SecRandomCopyBytes', 'aks_create_bag', 'aks_params_create', 'aks_params_set_data',
                  'aks_params_set_number', 'aks_params_get_der', 'aks_create_signing_key_with_params')
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage), self.endpoint(FAIL=stage) as run:
                result = run.endpoint.call('generate', attested=True, key_class=9)
                self.assertEqual(result['operation_stage'], stage)
                self.assertNotIn('identity', result)
                if stage == 'aks_params_create':
                    self.assertEqual(result['error'], 'keystore_parameters_unavailable')
                else:
                    self.assertEqual(result['status'], -701)
            for skipped in stages[index + 1:]:
                self.assertNotIn(skipped, run.stats['calls'])
            self.assertEqual(len(run.stats['unloads']), int(index >= 2))
            self.record('generation_failure:' + stage)

    def test_unusable_signatures_never_create_sessions_or_owned_remote_keys(self):
        for operation in ('sign_remote', 'session'):
            for mode in ('empty', 'null_with_size', 'zero_with_buffer', 'oversize'):
                with self.subTest(operation=operation, mode=mode), self.endpoint(
                        MODE_API='aks_sign_signing_key', MODE=mode) as run:
                    identity = self.generate(run.endpoint)
                    result = run.endpoint.call(operation, identity=identity, remote_ltk=REMOTE)
                    self.assertNotEqual(result['status'], 0)
                    self.assertEqual(result['native_status'], 0)
                    self.assertEqual(result['error'], 'invalid_signed_key_result')
                    self.assertNotIn('data', result)
                    self.assertNotIn('session', result)
                    self.assertEqual(run.endpoint.call('get_state', data=REMOTE)['error'], 'remote_key_not_owned')
                self.assertNotIn('aks_remote_session', run.stats['calls'])
                self.record('invalid_signature:' + operation + ':' + mode)

    def test_invalid_generation_outputs_are_rejected_and_owned_bags_unloaded(self):
        cases = [({'BAG': 'negative'}, 'invalid_keybag_result', 0),
                 ({'DER': 'null'}, 'keystore_parameters_invalid', 1),
                 ({'DER': 'empty'}, 'keystore_parameters_invalid', 1)]
        cases += [({'MODE_API': 'aks_create_signing_key_with_params', 'MODE': mode},
                   'invalid_signing_key_result', 1)
                  for mode in ('empty', 'null_with_size', 'zero_with_buffer', 'oversize')]
        for settings, error, unloads in cases:
            with self.subTest(settings=settings), self.endpoint(**settings) as run:
                result = run.endpoint.call('generate', attested=True, key_class=9)
                self.assertEqual(result['error'], error)
                self.assertNotIn('identity', result)
                self.assertNotIn('ltk', result)
            self.assertEqual(len(run.stats['unloads']), unloads)
            self.record('invalid_generation:' + str(settings))

    def test_unattested_creation_preserves_native_path_and_errors(self):
        for failure in ('', 'aks_create_signing_key'):
            with self.subTest(failure=failure), self.endpoint(FAIL=failure) as run:
                result = run.endpoint.call('generate', attested=False, key_class=9)
                self.assertEqual(result['status'], -701 if failure else 0)
                self.assertEqual(result['operation_stage'], 'aks_create_signing_key')
                self.assertEqual('identity' in result, not bool(failure))
            self.assertNotIn('aks_params_create', run.stats['calls'])
            self.assertEqual(len(run.stats['unloads']), 1)
            self.record('unattested_creation:' + (failure or 'success'))

    def test_validation_session_and_peer_failures_preserve_native_status(self):
        for operation, api in (('validate', 'aks_validate_local_key'), ('session', 'aks_remote_session'),
                               ('get_state', 'aks_remote_peer_get_state'), ('drop', 'aks_remote_peer_drop')):
            with self.subTest(operation=operation), self.endpoint(FAIL=api) as run:
                identity = self.generate(run.endpoint)
                if operation in ('validate', 'session'):
                    result = run.endpoint.call(operation, identity=identity, remote_ltk=REMOTE)
                    self.assertNotIn('session', result)
                else:
                    signed = run.endpoint.call('sign_remote', identity=identity, remote_ltk=REMOTE)['data']
                    result = run.endpoint.call(operation, data=signed)
                    if operation == 'drop':
                        # Failed drop must leave ownership available for retry.
                        self.assertEqual(run.endpoint.call('get_state', data=signed)['status'], 0)
                self.assertEqual(result['status'], -701)
            self.assertEqual(len(run.stats['unloads']), 1)
            self.assertEqual(run.stats['resets'], [])
            self.record('native_failure:' + api)

    def test_native_signing_failure_preserves_status(self):
        with self.endpoint(FAIL='aks_sign_signing_key') as run:
            result = self.session(run.endpoint, self.generate(run.endpoint))
            self.assertEqual(result['status'], -701)
            self.assertEqual(result['sign_status_hex'], '0xfffffd43')
            self.assertNotIn('session', result)
        self.assertNotIn('aks_remote_session', run.stats['calls'])
        self.record('native_signing_failure')

    def test_invalid_native_session_handles_are_not_forwarded_as_success(self):
        with self.endpoint(HANDLE='negative') as run:
            result = self.session(run.endpoint, self.generate(run.endpoint))
            self.assertNotEqual(result['status'], 0)
            self.assertEqual(result['native_status'], 0)
            self.assertEqual(result['error'], 'invalid_session_handle')
            self.assertNotIn('session', result)
        self.assertEqual(run.stats['resets'], [])
        self.record('negative_native_session')
        with self.endpoint(HANDLE='duplicate') as run:
            broker = AksBroker(run.endpoint)
            local = broker.execute({'operation': 'generate'})['data']
            signed = broker.execute({'operation': 'sign_remote', 'local_ltk': local, 'remote_ltk': REMOTE})['data']
            request = {'operation': 'session_signed', 'local_ltk': local, 'remote_ltk': signed}
            self.assertEqual(broker.execute(request)['status'], 0)
            with self.assertRaises(EndpointError):
                broker.execute(request)
            self.assertFalse(broker.execute({'operation': 'health'})['ready'])
        self.assertEqual(run.stats['resets'], [7])
        self.record('duplicate_native_session_rejected_by_broker')

    def test_session_output_boundaries_preserve_empty_success_and_native_errors(self):
        for operation, api in (('token', 'aks_remote_session_token'), ('step', 'aks_remote_session_step'),
                               ('setup', 'aks_remote_peer_setup'), ('confirm', 'aks_remote_peer_confirm')):
            for mode in ('normal', 'empty', 'zero_with_buffer', 'null_with_size', 'oversize', 'failure_with_data'):
                settings = {'MODE_API': api, 'MODE': mode}
                if mode == 'failure_with_data':
                    settings['FAIL'] = api
                with self.subTest(operation=operation, mode=mode), self.endpoint(**settings) as run:
                    session = self.session(run.endpoint, self.generate(run.endpoint))['session']
                    result = run.endpoint.call(operation, session=session, data=REMOTE)
                    if mode in ('null_with_size', 'oversize'):
                        self.assertNotEqual(result['status'], 0)
                        self.assertEqual(result['native_status'], 0)
                        self.assertEqual(result['error'], 'invalid_session_output')
                        self.assertNotIn('data', result)
                    elif mode == 'failure_with_data':
                        self.assertEqual(result['status'], -701)
                        self.assertNotIn('data', result)
                    else:
                        self.assertEqual(result['status'], 0)
                        self.assertEqual('data' in result, mode == 'normal')
                self.assertEqual(run.stats['resets'], [session])
                self.record('session_output:' + operation + ':' + mode)

    def test_malformed_field_types_leave_the_endpoint_usable_and_cleanup_owned_state(self):
        with self.endpoint() as run:
            session = self.session(run.endpoint, self.generate(run.endpoint))['session']
            for field in ('identity', 'remote_ltk', 'parameters', 'data', 'key_class', 'remote_key_class', 'flags', 'session', 'attested'):
                for value in ([], {}, None):
                    with self.subTest(field=field, value=value):
                        result = run.endpoint.call('generate', **{field: value})
                        self.assertEqual(result['error'], 'invalid_request_fields')
                        self.record('malformed_field:' + field + ':' + type(value).__name__)
            self.assertEqual(run.endpoint.call([])['error'], 'invalid_request_fields')
            self.assertEqual(run.endpoint.call('unknown')['error'], 'unknown_operation')
            self.assertEqual(run.endpoint.call('token', session=session)['status'], 0)
        self.assertEqual(run.stats['resets'], [session])
        self.assertEqual(len(run.stats['unloads']), 1)

    def test_native_capacity_and_ownership_are_enforced_before_private_calls(self):
        with self.endpoint() as run:
            identities = [self.generate(run.endpoint) for _ in range(8)]
            self.assertEqual(run.endpoint.call('generate')['error'], 'identity_limit_or_missing_dcrt')
            handles = [self.session(run.endpoint, identities[0])['session'] for _ in range(MAX_SESSIONS)]
            self.assertEqual(self.session(run.endpoint, identities[0])['error'], 'invalid_identity_key_or_session_limit')
            # Signing does not allocate a session and remains available at capacity.
            self.assertEqual(run.endpoint.call('sign_remote', identity=identities[0], remote_ltk=REMOTE)['status'], 0)
            self.assertEqual(run.endpoint.call('reset', session=999)['error'], 'session_not_owned')
            self.assertEqual(run.endpoint.call('reset', session=handles[0])['status'], 0)
            self.assertEqual(self.session(run.endpoint, identities[0])['status'], 0)
        self.assertEqual(len(run.stats['unloads']), 8)
        self.assertEqual(len(run.stats['resets']), MAX_SESSIONS + 1)
        self.assertNotIn(999, run.stats['resets'])
        self.record('identity_capacity:8')
        self.record('session_capacity:16_and_recovery')

    def test_reset_failure_retains_handle_for_final_cleanup(self):
        with self.endpoint(FAIL='aks_remote_session_reset') as run:
            session = self.session(run.endpoint, self.generate(run.endpoint))['session']
            self.assertEqual(run.endpoint.call('reset', session=session)['status'], -701)
        self.assertEqual(run.stats['resets'], [session, session])
        self.record('failed_reset_retains_owned_handle')

    def test_protocol_framing_and_oversized_request_cleanup(self):
        with self.endpoint() as run:
            session = self.session(run.endpoint, self.generate(run.endpoint))['session']
            for raw in (b'not-json', b'[]', b'null', b'"string"', b'{"operation":\xff}'):
                run.endpoint.socket.send_text(raw, time.monotonic() + 3)
                self.assertEqual(run.endpoint.read()['error'], 'invalid_json')
                self.record('invalid_json:' + raw.hex())
            # Announce an oversized frame without sending its payload, so the
            # service's reply is not lost to a reset from unread input.
            run.endpoint.socket.stream.sendall(struct.pack('!BBQ', 0x81, 0xff, 262145) + bytes(4))
            self.assertEqual(run.endpoint.read()['error'], 'request_too_large')
            with self.assertRaises(BridgeClosed):
                run.endpoint.socket.receive(time.monotonic() + 3)
            self.assertEqual(run.endpoint.poll(), 0)
        self.assertEqual(run.stats['resets'], [session])
        self.assertEqual(len(run.stats['unloads']), 1)
        self.record('oversized_request_releases_owned_state')

    def test_dropped_connection_releases_owned_state(self):
        with self.native() as run, self.service(run):
            with Endpoint(run.config, expected_certificate_sha256=hashlib.sha256(run.certificate.read_bytes()).hexdigest()) as endpoint:
                session = self.session(endpoint, self.generate(endpoint))['session']
                endpoint.socket.stream.close()  # No exit request: the Mac vanished.
                endpoint._failed = True
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status, report = request_json(run.config, TOKEN, 'GET', '/v1/status', timeout=3)
                    if report['active_sessions'] == 0:
                        break
                    time.sleep(.05)
                self.assertEqual(report['active_sessions'], 0)
        self.assertEqual(run.stats['resets'], [session])
        self.assertEqual(len(run.stats['unloads']), 1)
        self.record('dropped_connection_releases_owned_state')

    def test_wrong_token_cannot_complete_the_handshake(self):
        with self.native() as run, self.service(run):
            for token in ('0000-0000-0000-0000-0000-0000', TOKEN[:-1] + 'C'):
                with self.subTest(token=token), self.assertRaises(BridgeError) as caught:
                    request(run.config, token, 'GET', '/v1/status', timeout=3)
                self.assertEqual(caught.exception.code, 'bridge_token_rejected')
            with self.assertRaises(EndpointError) as caught:
                Endpoint(run.config, token='0000-0000-0000-0000-0000-0000',
                         expected_certificate_sha256=hashlib.sha256(run.certificate.read_bytes()).hexdigest())
            self.assertEqual(caught.exception.code, 'bridge_token_rejected')
        self.assertEqual(run.stats['calls'], {})
        self.record('wrong_token_rejected')

    def test_http_routes_status_certificate_and_errors(self):
        with self.native() as run, self.service(run, certificate=False):
            status, report = request_json(run.config, TOKEN, 'GET', '/v1/status')
            self.assertEqual((status, report['service'], report['certificate_available']), (200, 'mirra-bridge', False))
            self.assertEqual(report['protocol_version'], 2)
            self.assertEqual(request(run.config, TOKEN, 'GET', '/v1/certificate')[0], 404)
            with self.assertRaises(EndpointError) as caught:
                Endpoint(run.config, expected_certificate_sha256='0' * 64)
            self.assertEqual(caught.exception.code, 'device_certificate_unavailable')
            for issue in (False, True):
                status, exported = request_json(run.config, TOKEN, 'POST', '/v1/certificate', {'issue': issue})
                self.assertEqual(status, 200, exported)
                self.assertEqual(exported['issuance_requested'], issue)
                status, _, data = request(run.config, TOKEN, 'GET', '/v1/certificate')
                self.assertEqual((status, hashlib.sha256(data).hexdigest()), (200, exported['sha256']))
                certificate = run.service_directory / 'certificate.der'
                self.assertEqual(certificate.read_bytes(), data)
                self.assertEqual(certificate.stat().st_mode & 0o777, 0o600)
            self.assertTrue(request_json(run.config, TOKEN, 'GET', '/v1/status')[1]['certificate_available'])
            self.assertEqual(request_json(run.config, TOKEN, 'POST', '/v1/certificate', {'issue': 'yes'})[0], 400)
            self.assertEqual(request_json(run.config, TOKEN, 'GET', '/v1/unknown')[0], 404)
            self.assertEqual(request_json(run.config, TOKEN, 'DELETE', '/v1/status')[0], 405)
            self.assertEqual(request_json(run.config, TOKEN, 'GET', '/v1/session')[0], 400)
        self.assertFalse(run.stats['real_issuer_contacted'])
        self.record('http_routes')

    def test_http_certificate_failure_keeps_existing_certificate(self):
        with self.native(FAIL='MAECopyDCRTWithError') as run, self.service(run):
            status, reply = request_json(run.config, TOKEN, 'POST', '/v1/certificate', {'issue': False})
            self.assertEqual((status, reply['error']), (409, 'cached_certificate_unavailable'))
            self.assertEqual((run.service_directory / 'certificate.der').read_bytes(), b'SYNTHETIC-CERTIFICATE')
        self.record('http_certificate_failure_preserves_certificate')

    def test_certificate_renewal_rechecks_the_cache_without_reissuing(self):
        original = bytes(1024)
        fingerprint = hashlib.sha256(original).hexdigest()
        request_body = {'issue': True, 'replace_expired_sha256': fingerprint}
        for changes, expected in ((0, 409), (1, 200)):
            with self.subTest(changes=changes), self.native(CERT_CHANGES_AFTER=changes) as run, self.service(run):
                certificate = run.service_directory / 'certificate.der'
                certificate.write_bytes(original)
                status, reply = request_json(run.config, TOKEN, 'POST', '/v1/certificate', request_body)
                self.assertEqual(status, expected, reply)
                if changes:
                    self.assertNotEqual(certificate.read_bytes(), original)
                    self.assertEqual(reply['sha256'], hashlib.sha256(certificate.read_bytes()).hexdigest())
                    self.assertFalse(request_json(run.config, TOKEN, 'POST', '/v1/certificate', request_body)[1]['issuance_requested'])
                else:
                    self.assertEqual(reply['error'], 'certificate_unchanged')
                    self.assertEqual(certificate.read_bytes(), original)
            self.assertEqual(run.stats['calls']['MAECopyDCRTWithError'], 2)
            self.assertEqual(run.stats['calls']['MAEIssueDCRTWithCallback'], 1)
        self.record('certificate_renewal_rechecks_cache_and_never_reissues_within_request')

    def test_session_limit_and_missing_keystore(self):
        with self.native() as run, self.service(run):
            digest = hashlib.sha256(run.certificate.read_bytes()).hexdigest()
            sessions = [Endpoint(run.config, expected_certificate_sha256=digest) for _ in range(4)]
            try:
                with self.assertRaises(EndpointError) as caught:
                    Endpoint(run.config, expected_certificate_sha256=digest)
                self.assertEqual(caught.exception.code, 'bridge_session_limit')
            finally:
                for endpoint in sessions:
                    endpoint.close()
        with self.native(MISSING='aks_create_bag') as run, self.service(run):
            status, report = request_json(run.config, TOKEN, 'GET', '/v1/status')
            self.assertEqual((status, report['required_symbols_available']), (200, False))
            with self.assertRaises(EndpointError) as caught:
                Endpoint(run.config, expected_certificate_sha256=hashlib.sha256(run.certificate.read_bytes()).hexdigest())
            self.assertEqual(caught.exception.code, 'required_keystore_symbols_unavailable')
            self.assertEqual(request_json(run.config, TOKEN, 'POST', '/v1/certificate', {})[0], 409)
        self.record('session_limit_and_missing_keystore')

    def test_certificate_paths_apis_sizes_and_virtual_callback_deadline(self):
        cases = (
            ('cached', {}, '--export-certificate', 0, None),
            ('issue', {}, '--issue-certificate', 0, None),
            ('delayed', {'ISSUE': 'delayed'}, '--issue-certificate', 0, None),
            ('timeout', {'ISSUE': 'timeout'}, '--issue-certificate', 1, 'certificate_issuance_failed'),
            ('callback_error', {'FAIL': 'MAEIssueDCRTWithCallback'}, '--issue-certificate', 1, 'certificate_issuance_failed'),
            ('copy_error', {'FAIL': 'MAECopyDCRTWithError'}, '--export-certificate', 1, 'cached_certificate_unavailable'),
            ('missing_copy', {'MISSING': 'MAECopyDCRTWithError'}, '--export-certificate', 1, 'certificate_api_unavailable'),
            ('missing_issue', {'MISSING': 'MAEIssueDCRTWithCallback'}, '--issue-certificate', 1, 'certificate_issuance_api_unavailable'),
            ('empty', {'CERT_SIZE': 0}, '--export-certificate', 1, 'cached_certificate_unavailable'),
            ('max', {'CERT_SIZE': 1048576}, '--export-certificate', 0, None),
            ('oversize', {'CERT_SIZE': 1048577}, '--export-certificate', 1, 'cached_certificate_unavailable'),
            ('invalid_type', {'CERT_TYPE': 'invalid'}, '--export-certificate', 1, 'cached_certificate_unavailable'),
            ('exists', {}, '--export-certificate', 1, 'output_already_exists'),
            ('symlink', {}, '--export-certificate', 1, 'output_already_exists'))
        for name, settings, action, code, error in cases:
            with self.subTest(name=name), self.native(**settings) as run:
                output = run.directory / 'export.der'
                if name == 'exists':
                    output.write_bytes(b'PRESERVE')
                if name == 'symlink':
                    output.symlink_to(run.certificate)
                response = subprocess.run([str(BINARY), action, str(output)], env=run.env,
                    capture_output=True, timeout=3)
                value = json.loads(response.stdout)
                self.assertEqual(response.returncode, code, response.stderr.decode())
                if error:
                    self.assertEqual(value['error'], error)
                    if name not in ('exists', 'symlink'):
                        self.assertFalse(output.exists())
                else:
                    self.assertTrue(value['certificate_exported'])
                    self.assertEqual(output.stat().st_size, int(settings.get('CERT_SIZE', 1024)))
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(run.certificate.read_bytes(), b'SYNTHETIC-CERTIFICATE')
            self.assertFalse(run.stats['real_issuer_contacted'])
            self.record('certificate:' + name)


def main():
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=BINARY)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--model', default=PROFILE['MODEL'])
    parser.add_argument('--ios-version', default=PROFILE['IOS'])
    parser.add_argument('--ios-build', default=PROFILE['BUILD'])
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    PROFILE.update(MODEL=args.model, IOS=args.ios_version, BUILD=args.ios_build)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EndpointProtocolTests))
    report = {'passed': result.wasSuccessful(), 'test_methods': result.testsRun,
        'scenarios': SCENARIOS, 'scenario_count': len(SCENARIOS), 'real_aks_accessed': False,
        'real_issuer_contacted': False, 'physical_device_compatibility_verified': False,
        'virtual_issuance_clock': True, 'metadata_profile': PROFILE,
        'firmware_emulated': False,
        'suite_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ('tests/endpoint-protocol.m', 'scripts/transport.py', 'scripts/bridgeclient.py',
                         'scripts/keystore.py', 'scripts/wire.py',
                         'src/phone/keystore-symbols.h', 'src/phone/cache-symbols.h')},
        'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        'endpoint_sha256': hashlib.sha256((ROOT / 'src/phone/endpoint.m').read_bytes()).hexdigest()}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'scenarios'}))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
