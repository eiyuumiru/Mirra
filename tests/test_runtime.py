import errno
import json
from pathlib import Path
import shlex
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from transport import Endpoint,EndpointError,MAX_REPLY
from configuration import ConfigError,load_config
from usbmux import select_device
from bridgepaths import helper_command
from bridgefixture import BridgeFixture, GREETING


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.path = self.root/'settings.json'

    def config(self,data):
        self.path.write_text(json.dumps(data))
        return load_config(self.path,root=self.root)

    def test_defaults_do_not_select_a_reference_phone(self):
        c = self.config({})
        self.assertEqual((c.transport,c.product_type,c.listen_port,c.device_port,c.seconds),
                         ('ssh','',2222,22,1800))
        self.assertEqual(c.certificate_file,self.root/'private/bridge/certificate.der')

    def test_another_device_and_custom_paths(self):
        c = self.config({'backend':{'usb':{'product_type':'iPhone12,3','serial':'TEST-DEVICE','listen_port':2323},
                                     'ssh':{'identity_file':'private/other/key'},'certificate_file':'private/other/cert.der'}})
        self.assertEqual(c.product_type,'iPhone12,3')
        self.assertEqual(c.serial,'TEST-DEVICE')
        self.assertEqual(c.identity_file,self.root/'private/other/key')

    def test_ssh_remote_command_preserves_literal_paths(self):
        remote = "/var/mobile/path with spaces/$(touch unwanted);'endpoint"
        c = self.config({'backend':{'transport':'ssh','ssh':{'host':'192.0.2.5','port':2223,
            'host_key_alias':'owned-backend','user_file':'user','remote_endpoint':remote}}})
        c.user_file.write_text('mobile\n')
        command = c.ssh_command(helper_command([c.remote_endpoint, c.remote_certificate], c.path_mode))
        self.assertIn('StrictHostKeyChecking=yes',command)
        self.assertIn('HostKeyAlias=owned-backend',command)
        self.assertEqual(command[-2],'192.0.2.5')
        self.assertEqual(shlex.split(command[-1]),[remote,c.remote_certificate])

    def test_usb_port_overrides_ssh_port(self):
        c = self.config({'backend':{'transport':'usb','usb':{'product_type':'iPhone11,2','listen_port':2323},'ssh':{'port':8888,'user_file':'user'}}})
        c.user_file.write_text('mobile')
        command = c.ssh_command(helper_command([c.remote_endpoint, c.remote_certificate], c.path_mode))
        self.assertEqual(command[command.index('-p')+1],'2323')
        self.assertEqual(command[-2],'127.0.0.1')

    def test_ssh_known_host_path_with_spaces_is_one_configuration_token(self):
        c = self.config({'backend':{'ssh':{'known_hosts_file':'Application Support/backend/known_hosts',
                                         'user_file':'user'}}})
        c.user_file.write_text('mobile')
        option = next(arg for arg in c.ssh_command(helper_command([c.remote_endpoint, c.remote_certificate], c.path_mode)) if arg.startswith('UserKnownHostsFile='))
        # Protect the nested configuration-value boundary, in addition to argv.
        # The installed-path live SSH test separately verifies OpenSSH behavior.
        self.assertEqual(shlex.split(option.partition('=')[2]),[str(c.known_hosts_file)])

    def test_invalid_settings_fail_before_device_access(self):
        invalid = [[],{'schema_version':True},{'backend':{'usb':{'listen_port':True}}},
            {'backend':{'usb':{'listen_port':65536}}},{'backend':{'tranpsort':'ssh'}},
            {'backend':{'transport':'usb','usb':{'product_type':'','serial':''}}},
            {'backend':{'ssh':{'host':'-oProxyCommand=bad'}}},
            {'backend':{'ssh':{'remote_endpoint':'relative'}}},
            {'backend':{'ssh':{'remote_certificate':'/path\ncommand'}}}]
        for data in invalid:
            with self.subTest(data=data),self.assertRaises(ConfigError):
                self.config(data)

    def test_missing_explicit_config_is_not_defaulted(self):
        with self.assertRaises(ConfigError):
            load_config(self.root/'missing.json',root=self.root)

    def test_session_staging_preserves_device_settings(self):
        original=self.config({'backend':{'transport':'ssh','ssh':{'host':'192.0.2.4','port':2223}},
                              'host':{'runtime_directory':'runtime/staged'}})
        staged=self.config(original.as_dict())
        self.assertEqual(original,staged)

    def test_roothide_profile_round_trip_preserves_mode_and_literal_paths(self):
        original = self.config({'backend': {'ssh': {'path_mode': 'roothide', 'user_file': 'user',
            'remote_endpoint': "/usr/local/libexec/Mirra/endpoint 'with' spaces"}}})
        original.user_file.write_text('root')
        command = original.ssh_command(helper_command([original.remote_endpoint, original.remote_certificate], original.path_mode))
        arguments = shlex.split(command[-1])
        self.assertEqual(arguments[-2:], [original.remote_endpoint, original.remote_certificate])
        self.assertIn('jbroot', arguments[2])
        self.assertIn('BatchMode=yes', command)
        self.assertEqual(self.config(original.as_dict()), original)

    def test_native_profile_does_not_add_a_new_setting_or_launcher(self):
        original = self.config({})
        self.assertEqual(original.path_mode, 'native')
        self.assertNotIn('path_mode', original.as_dict()['backend']['ssh'])

    def test_invalid_path_modes_are_rejected_before_access(self):
        for mode in ('guess', '', None, [], True):
            with self.subTest(mode=mode), self.assertRaises(ConfigError):
                self.config({'backend': {'ssh': {'path_mode': mode}}})


class USBSelectionTests(unittest.TestCase):
    @staticmethod
    def device(identifier,serial='BACKEND',transport='USB'):
        return {'DeviceID':identifier,'Properties':{'SerialNumber':serial,'ConnectionType':transport}}

    def test_replug_uses_new_identifier(self):
        first = select_device([self.device(4)],serial='BACKEND')
        next_ = select_device([self.device(17)],serial='BACKEND')
        self.assertEqual(first['DeviceID'],4)
        self.assertEqual(next_['DeviceID'],17)

    def test_same_model_is_ambiguous_without_serial(self):
        devices = [self.device(1,'FIRST'),self.device(2,'SECOND')]
        with self.assertRaises(ConnectionError):
            select_device(devices,product='iPhone11,2',product_reader=lambda _: 'iPhone11,2')
        self.assertEqual(select_device(devices,serial='SECOND')['DeviceID'],2)

    def test_serial_does_not_override_wrong_model(self):
        with self.assertRaises(ConnectionError):
            select_device([self.device(1)],serial='BACKEND',product='iPhone11,2',product_reader=lambda _: 'iPhone14,5')

    def test_network_and_unreadable_devices_are_excluded(self):
        with self.assertRaises(ConnectionError):
            select_device([self.device(1,transport='Network')],serial='BACKEND')
        def unavailable(_):
            raise OSError('disconnected')
        with self.assertRaises(ConnectionError):
            select_device([self.device(1)],product='iPhone11,2',product_reader=unavailable)


class TransportTests(unittest.TestCase):
    def bridge(self, handler=None, **kwargs):
        fixture = BridgeFixture(handler, **kwargs)
        fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        return fixture

    def test_unready_greeting_preserves_known_capability_failure_without_secrets(self):
        greeting = {'ready': False, 'error': 'required_keystore_symbols_unavailable',
                    'missing_symbols': ['aks_remote_session'], 'os_version': '15.8.4',
                    'process_architecture': 'arm64', 'serial': 'private-serial', 'dcrt': 'private-certificate'}
        bridge = self.bridge(greeting=greeting)
        with self.assertRaises(EndpointError) as caught:
            bridge.connect()
        self.assertEqual(caught.exception.code, greeting['error'])
        self.assertEqual(caught.exception.details['capabilities']['missing_symbols'], ['aks_remote_session'])
        self.assertNotIn('private-', json.dumps(caught.exception.details))
        self.assertTrue(bridge.closed.wait(1))

    def test_mismatched_certificate_and_unknown_protocol_are_rejected(self):
        greetings = [dict(GREETING, protocol_version=1), dict(GREETING, dcrt_sha256='a' * 64)]
        for greeting in greetings:
            with self.subTest(greeting=greeting):
                bridge = self.bridge(greeting=greeting)
                with self.assertRaises(EndpointError):
                    bridge.connect()
                self.assertTrue(bridge.closed.wait(1))

    def test_missing_fingerprint_does_not_satisfy_explicit_certificate_binding(self):
        bridge = self.bridge(greeting={'ready': True, 'protocol_version': 2})
        with self.assertRaisesRegex(EndpointError, 'certificates do not match'):
            bridge.connect(expected_certificate_sha256='a' * 64)

    def test_multiple_buffered_frames_are_not_lost(self):
        bridge = self.bridge(lambda request, peer: None, initial=({'status': 0},))
        endpoint = bridge.connect()
        self.assertEqual(endpoint.call('validate'), {'status': 0})
        endpoint._failed = True  # The fixture intentionally has no exit reply.

    def test_roundtrip_and_graceful_close(self):
        bridge = self.bridge(lambda request, peer: {'operation': request['operation'], 'status': 0})
        endpoint = bridge.connect()
        self.assertTrue(endpoint.certificate_binding_verified)
        self.assertEqual(endpoint.call('validate')['operation'], 'validate')
        endpoint.close()
        endpoint.close()
        self.assertTrue(bridge.closed.wait(1))
        self.assertEqual([r['operation'] for r in bridge.requests], ['validate', 'exit'])
        self.assertEqual(endpoint.socket.stream.fileno(), -1)

    def test_partial_response_times_out_and_poisoned_session_is_not_reused(self):
        def partial(request, peer):
            peer.stream.sendall(bytes((0x81, 12)) + b'{"status":')
            peer.stop.wait(5)
        bridge = self.bridge(partial, timeout=.15)
        endpoint = bridge.connect()
        started = time.monotonic()
        with self.assertRaisesRegex(EndpointError, 'timed out') as caught:
            endpoint.call('generate')
        self.assertEqual(caught.exception.code, 'endpoint_reply_timeout')
        self.assertEqual(caught.exception.details['operation'], 'generate')
        self.assertIs(endpoint.failure, caught.exception)
        self.assertLess(time.monotonic() - started, 1)
        with self.assertRaisesRegex(EndpointError, 'unavailable'):
            endpoint.call('validate')
        self.assertIs(endpoint.failure, caught.exception)
        endpoint.close()
        self.assertEqual(endpoint.socket.stream.fileno(), -1)

    def test_invalid_and_oversized_replies_are_rejected(self):
        for reply in (b'[]', b'invalid', b'x' * (MAX_REPLY + 1)):
            with self.subTest(length=len(reply)):
                bridge = self.bridge(lambda request, peer: reply)
                endpoint = bridge.connect()
                with self.assertRaises(EndpointError) as caught:
                    endpoint.call('validate')
                expected = 'endpoint_reply_too_large' if len(reply) > MAX_REPLY else 'endpoint_invalid_reply'
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(caught.exception.details['operation'], 'validate')
                with self.assertRaisesRegex(EndpointError, 'unavailable'):
                    endpoint.call('validate')
                endpoint.close()

    def test_eof_and_an_observed_disconnect_have_distinct_errors(self):
        def eof(request, peer):
            peer.stream.close()
        endpoint = self.bridge(eof).connect()
        with self.assertRaises(EndpointError) as caught:
            endpoint.call('validate')
        self.assertEqual(caught.exception.code, 'endpoint_eof')
        self.assertNotIn('exit_code', caught.exception.details)
        endpoint.close()
        closed = self.bridge(before_requests=lambda peer: peer.stream.close())
        endpoint = closed.connect()
        self.assertTrue(closed.closed.wait(1))
        self.assertEqual(endpoint.poll(), 0)
        with self.assertRaises(EndpointError) as caught:
            endpoint.call('validate')
        self.assertEqual(caught.exception.code, 'endpoint_disconnected')

    def test_a_stalled_socket_reports_a_write_timeout_without_request_material(self):
        bridge = self.bridge(timeout=.15, before_requests=lambda peer: peer.stop.wait(5))
        endpoint = bridge.connect()
        with self.assertRaises(EndpointError) as caught:
            endpoint.call('setup', data='x' * (MAX_REPLY - 256))
        self.assertEqual(caught.exception.code, 'endpoint_write_timeout')
        self.assertGreater(caught.exception.details['request_bytes'], 200000)
        self.assertNotIn('x' * 32, json.dumps(caught.exception.details))

    def test_io_errors_report_the_stage_and_abandon_the_socket(self):
        endpoint = self.bridge().connect()
        with patch.object(endpoint.socket, 'send_text', side_effect=OSError(errno.EPIPE, 'private input')), \
                self.assertRaises(EndpointError) as caught:
            endpoint.call('validate')
        self.assertEqual(caught.exception.code, 'endpoint_io_error')
        self.assertEqual(caught.exception.details['stage'], 'write')
        self.assertNotIn('private input', json.dumps(caught.exception.details))
        with self.assertRaisesRegex(EndpointError, 'unavailable'):
            endpoint.call('validate')

    def test_wrapping_keeps_existing_error_code_and_details(self):
        endpoint = self.bridge().connect()
        error = EndpointError('Known failure', 'known_failure', {'stage': 'known_stage'})
        with patch.object(endpoint, 'read', side_effect=error), self.assertRaises(EndpointError) as caught:
            endpoint.call('validate')
        self.assertEqual(caught.exception.code, error.code)
        self.assertEqual(caught.exception.details['stage'], 'known_stage')
        self.assertIs(endpoint.failure, caught.exception)

    def test_failed_start_closes_its_socket(self):
        bridge = self.bridge(greeting={'ready': False})
        with self.assertRaises(EndpointError):
            bridge.connect()
        self.assertTrue(bridge.closed.wait(1))
        self.assertEqual(bridge.websocket.stream.fileno(), -1)

    def test_close_interrupts_an_inflight_request(self):
        bridge = self.bridge(lambda request, peer: peer.stop.wait(5) and None, timeout=20)
        endpoint = bridge.connect()
        errors = []
        def pending():
            try:
                endpoint.call('validate')
            except EndpointError as error:
                errors.append(str(error))
        thread = threading.Thread(target=pending)
        thread.start()
        self.assertTrue(bridge.request_received.wait(1))
        self.assertIsNone(endpoint.poll())
        started = time.monotonic()
        endpoint.close()
        thread.join(2)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(errors)


if __name__ == '__main__':
    unittest.main()
