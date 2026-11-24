from pathlib import Path
import json
import sys
import time
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from keystore import AksBroker, MAX_SESSIONS, NO_MEMORY, SESSION_BASE, SESSION_END, UNAVAIWORKSPACELE, verify_attested_key
from transport import EndpointError, transport_details
from bridgefixture import BridgeFixture
from test_provisioning import fixture_ltk


class BrokerSessionTests(unittest.TestCase):
    def broker(self):
        endpoint = Mock(timeout=1)
        endpoint.failure = None
        endpoint.poll.return_value = None
        broker = AksBroker(endpoint)
        broker.identities['owned-local'] = 'private-identity'
        return broker, endpoint

    def session(self, broker):
        return broker.execute({'operation': 'session_signed', 'local_ltk': 'owned-local',
                               'remote_ltk': 'owned-remote', 'flags': 2})

    def test_invalid_successful_generation_never_publishes_a_broker_identity(self):
        broker, endpoint = self.broker()
        endpoint.call.return_value = {'status': 0, 'error': 'keystore_parameters_unavailable',
                                      'operation_stage': 'aks_params_create'}
        result = broker.execute({'operation': 'generate', 'key_class': 9})
        self.assertEqual(result['status'], UNAVAIWORKSPACELE)
        self.assertEqual(result['backend_operation']['status'], 0)
        self.assertFalse(broker.classes)
        self.assertFalse(broker.wire_keys)
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])

    def test_malformed_generation_and_unsupported_wire_layout_never_publish_keys(self):
        for fields in ({'status': False}, {'identity': ['bad-type']},
                       {'ltk': 123}, {'ltk': 'dW5zdXBwb3J0ZWQ='}):
            with self.subTest(fields=fields):
                broker, endpoint = self.broker()
                endpoint.call.return_value = dict(
                    {'status': 0, 'identity': 'private-identity', 'ltk': fixture_ltk()}, **fields)
                result = broker.execute({'operation': 'generate', 'key_class': 9})
                self.assertEqual(result['status'], UNAVAIWORKSPACELE)
                self.assertFalse(broker.classes)
                self.assertFalse(broker.wire_keys)
                self.assertNotIn('ltk', result)
                self.assertFalse(broker.execute({'operation': 'health'})['ready'])

    def test_handles_remain_distinct_after_thousands_of_reconnects(self):
        broker, endpoint = self.broker()
        endpoint.call.side_effect = lambda op, **kw: {'status': 0, 'session': 7} if op == 'session_signed' else {'status': 0}
        old = None
        for _ in range(4100):
            current = self.session(broker)['session']
            if old is not None:
                self.assertEqual(broker.execute({'operation': 'token', 'session': old}), {'error': 'session_not_owned'})
            self.assertEqual(broker.execute({'operation': 'reset', 'session': current})['status'], 0)
            old = current
        last = self.session(broker)['session']
        endpoint.call.reset_mock()
        self.assertGreater(last, SESSION_BASE + 4096)
        self.assertEqual(broker.reset_owned_sessions()['reset_count'], 1)
        self.assertEqual(endpoint.call.call_count, 1)
        self.assertEqual(endpoint.call.call_args.kwargs['session'], 7)
        self.assertFalse(broker.sessions)

    def test_reset_failure_keeps_ownership_until_successful_cleanup(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + 3: 97, SESSION_BASE + 9000: 204}
        endpoint.call.side_effect = [{'status': -1}, {'status': 0}]
        result = broker.reset_owned_sessions()
        self.assertEqual((result['status'], result['reset_count'], result['remaining_sessions']), (-1, 1, 1))
        self.assertEqual(broker.sessions, {SESSION_BASE + 3: 97})
        self.assertEqual(broker.execute({'operation': 'health'})['error'], 'owned_session_reset_failed')
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])
        endpoint.call.side_effect = None
        endpoint.call.reset_mock()
        self.assertEqual(self.session(broker)['error'], 'broker_requires_restart')
        endpoint.call.assert_not_called()
        endpoint.call.return_value = {'status': 0}
        self.assertEqual(broker.reset_owned_sessions()['remaining_sessions'], 0)
        # Teardown may retry known handles, but only a fresh broker may serve
        # authentication again after failure; old cached identities stay retired.
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])

    def test_single_reset_can_retry_without_losing_ownership(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + 3: 97}
        endpoint.call.return_value = {'status': -2}
        self.assertEqual(broker.execute({'operation': 'reset', 'session': SESSION_BASE + 3})['status'], -2)
        self.assertIn(SESSION_BASE + 3, broker.sessions)
        endpoint.call.return_value = {'status': 0}
        self.assertEqual(broker.reset_owned_sessions()['remaining_sessions'], 0)
        self.assertTrue(broker.execute({'operation': 'health'})['ready'])

    def test_reset_transport_failure_stops_without_guessing_or_forgetting_handles(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + i: i + 80 for i in range(1, 17)}
        endpoint.call.side_effect = EndpointError('offline')
        result = broker.reset_owned_sessions()
        self.assertEqual(result['status'], UNAVAIWORKSPACELE)
        self.assertEqual(endpoint.call.call_count, 1)
        self.assertEqual(len(broker.sessions), 16)
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])

    def test_validation_failure_returns_explicit_unhealthy_reply(self):
        for response in ({'status': -7}, {'status': False}, {}, EndpointError('lost command stream')):
            with self.subTest(response=response):
                broker, endpoint = self.broker()
                broker.classes[9] = {'identity': 'private-identity'}
                if isinstance(response, Exception):
                    endpoint.call.side_effect = response
                else:
                    endpoint.call.return_value = response
                self.assertFalse(broker.execute({'operation': 'health'})['ready'])
                self.assertFalse(broker.execute({'operation': 'health'})['ready'])
                endpoint.call.assert_called_once_with('validate', identity='private-identity')

    def test_health_retains_the_first_transport_failure_without_request_material(self):
        broker, endpoint = self.broker()
        broker.classes[9] = {'identity': 'private-identity'}
        endpoint.call.side_effect = EndpointError('private input', 'endpoint_reply_timeout',
            {'operation': 'validate', 'reply_bytes': 9, 'identity': 'private-identity',
             'data': 'private-key', 'stderr': 'private-stderr'})
        first = broker.execute({'operation': 'health'})
        endpoint.poll.return_value = 0
        second = broker.execute({'operation': 'health'})
        self.assertEqual(first, second)
        self.assertEqual(first['transport_failure'],
                         {'code': 'endpoint_reply_timeout', 'operation': 'validate', 'reply_bytes': 9})
        self.assertNotIn('private-', json.dumps(first))
        endpoint.call.assert_called_once()

    def test_health_uses_the_abandoned_streams_original_error(self):
        broker, endpoint = self.broker()
        broker.classes[9] = {'identity': 'private-identity'}
        endpoint.failure = EndpointError('Original write failure', 'endpoint_io_error',
                                        {'stage': 'write', 'errno': 32})
        endpoint.call.side_effect = EndpointError('Session is now unavailable', 'endpoint_unavailable')
        response = broker.execute({'operation': 'health'})
        self.assertFalse(response['ready'])
        self.assertEqual(response['transport_failure']['code'], 'endpoint_io_error')
        endpoint.call.assert_not_called()

    def test_malformed_diagnostic_values_cannot_disrupt_an_unhealthy_reply(self):
        error = EndpointError('private input', ['private-code'],
                              {'operation': ['private-operation'], 'errno': True, 'stage': {}})
        self.assertEqual(transport_details(error), {'code': 'endpoint_error'})

    def test_reset_transport_details_remain_available_during_recovery(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + 1: 97}
        endpoint.call.side_effect = EndpointError('Closed stream', 'endpoint_eof',
                                                 {'operation': 'reset', 'data': 'private-input'})
        result = broker.reset_owned_sessions()
        self.assertEqual(result['transport_failure'], {'code': 'endpoint_eof', 'operation': 'reset'})
        self.assertEqual(broker.execute({'operation': 'health'})['transport_failure'], result['transport_failure'])
        self.assertEqual(broker.sessions, {SESSION_BASE + 1: 97})

    def test_malformed_reset_status_requires_recovery_and_preserves_handle(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + 1: 97}
        endpoint.call.return_value = {'status': False}
        self.assertEqual(broker.reset_owned_sessions()['status'], UNAVAIWORKSPACELE)
        self.assertEqual(broker.sessions, {SESSION_BASE + 1: 97})
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])

    def test_invalid_resets_and_empty_cleanup_never_touch_endpoint(self):
        broker, endpoint = self.broker()
        self.assertEqual(broker.reset_owned_sessions()['status'], 0)
        for value in (-1, 7, SESSION_BASE + 2, True, '7', None):
            self.assertEqual(broker.execute({'operation': 'reset', 'session': value}), {'error': 'session_not_owned'})
        endpoint.call.assert_not_called()

    def test_capacity_and_namespace_are_checked_before_allocating_remote_sessions(self):
        broker, endpoint = self.broker()
        broker.sessions = {SESSION_BASE + i: i for i in range(1, MAX_SESSIONS + 1)}
        self.assertEqual(self.session(broker)['status'], NO_MEMORY)
        broker.sessions.clear()
        broker.counter = SESSION_END - SESSION_BASE - 1
        self.assertEqual(self.session(broker)['error'], 'session_namespace_exhausted')
        endpoint.call.assert_not_called()

    def test_endpoint_response_is_not_mutated_and_invalid_handle_is_rejected(self):
        broker, endpoint = self.broker()
        reply = {'status': 0, 'session': 12}
        endpoint.call.return_value = reply
        self.assertEqual(self.session(broker)['session'], SESSION_BASE + 1)
        self.assertEqual(reply['session'], 12)
        with self.assertRaises(EndpointError):
            self.session(broker)
        self.assertFalse(broker.execute({'operation': 'health'})['ready'])
        self.assertEqual(self.session(broker)['error'], 'broker_requires_restart')

    def test_many_slow_resets_share_one_real_transport_deadline(self):
        def delayed(request, peer):
            self.assertNotIn('_deadline', request)
            time.sleep(.08)
            return {'status': 0}
        with BridgeFixture(delayed, timeout=.14) as bridge:
            endpoint = bridge.connect()
            broker = AksBroker(endpoint)
            broker.sessions = {SESSION_BASE + i: i for i in range(1, 17)}
            start = time.monotonic()
            result = broker.reset_owned_sessions()
            self.assertLess(time.monotonic() - start, .6)
            self.assertEqual(result['status'], UNAVAIWORKSPACELE)
            self.assertEqual(result['reset_count'], 1)
            self.assertEqual(result['remaining_sessions'], 15)
            with self.assertRaises(EndpointError):
                endpoint.call('validate')


class AttestedKeyTests(unittest.TestCase):
    def endpoint(self):
        endpoint = Mock()
        endpoint.ready = {'product_type': 'iPhone10,5', 'os_version': '16.7.10',
                          'os_build': '20H350', 'process_architecture': 'arm64',
                          'serial': 'private-serial', 'dcrt_sha256': 'private-certificate'}
        return endpoint

    def test_native_failure_keeps_exact_status_and_does_not_call_validate(self):
        endpoint = self.endpoint()
        endpoint.call.return_value = {'status': -7, 'status_hex': 'untrusted-status',
                                      'operation_stage': 'aks_create_signing_key_with_params',
                                      'identity': 'private-identity', 'ltk': 'private-key'}
        with self.assertRaises(EndpointError) as caught:
            verify_attested_key(endpoint)
        error = caught.exception
        self.assertEqual(error.code, 'bridge_attested_key_unavailable')
        self.assertEqual(error.details['status'], -7)
        self.assertEqual(error.details['status_hex'], '0xfffffff9')
        self.assertEqual(error.details['operation_stage'], 'aks_create_signing_key_with_params')
        self.assertEqual(error.details['capabilities']['product_type'], 'iPhone10,5')
        self.assertNotIn('private-', json.dumps(error.details))
        endpoint.call.assert_called_once_with('generate', attested=True, key_class=9)

    def test_malformed_successes_and_parameters_failure_are_rejected(self):
        for response in ({'status': False, 'identity': 'id', 'ltk': fixture_ltk()},
                         {'status': 0, 'identity': 'id'},
                         {'status': 0, 'identity': 'id', 'ltk': fixture_ltk(), 'error': 'invalid_signing_key_result'}):
            endpoint = self.endpoint()
            endpoint.call.return_value = response
            with self.subTest(response=response), self.assertRaises(EndpointError):
                verify_attested_key(endpoint)
            self.assertEqual(endpoint.call.call_count, 1)

    def test_validation_failure_and_unsupported_wire_format_are_distinct(self):
        endpoint = self.endpoint()
        generated = {'status': 0, 'identity': 'private-identity', 'ltk': fixture_ltk()}
        endpoint.call.side_effect = [generated, {'status': -9, 'operation_stage': 'aks_validate_local_key'}]
        with self.assertRaises(EndpointError) as caught:
            verify_attested_key(endpoint)
        self.assertEqual(caught.exception.code, 'bridge_attested_key_rejected')
        self.assertEqual(caught.exception.details['status'], -9)
        endpoint.call.side_effect = [{**generated, 'ltk': 'dW5zdXBwb3J0ZWQ='}, {'status': 0}]
        with self.assertRaises(EndpointError) as caught:
            verify_attested_key(endpoint)
        self.assertEqual(caught.exception.code, 'bridge_key_layout_unsupported')
        endpoint.call.side_effect = [generated, {'status': 0}]
        self.assertTrue(verify_attested_key(endpoint)['original_fields_byte_identical'])
