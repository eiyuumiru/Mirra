from dataclasses import replace
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from bridgeclient import BRIDGE_REVISION, BridgeTimeout, bridge_revision
from bridgepaths import ROOTHIDE_CODE_ROOT, ROOTHIDE_ENTITLEMENTS
from bridgeupdate import confirm_revision, update_bridge
from configuration import load_config
from provisioning import RemoteSetupError, SERVICE_DIRECTORY, SERVICE_LABEL


def status(revision=None):
    value = {'service': 'mirra-bridge', 'protocol_version': 2}
    if revision is not None:
        value['bridge_revision'] = revision
    return value


class BridgeUpdateTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.source = Path(scratch.name)
        (self.source / 'build').mkdir()
        (self.source / 'config').mkdir()
        (self.source / 'build/endpoint').write_bytes(b'fixture executable')
        (self.source / 'config/endpoint.plist').write_bytes(plistlib.dumps({'fixture-entitlement': True}))
        self.config = replace(load_config(root=self.source), remote_endpoint='/var/mobile/Mirra/endpoint',
                              service_port=47820)
        self.token = 'A' * 24
        self.daemon = plistlib.dumps({'Label': SERVICE_LABEL, 'ProgramArguments':
            [self.config.remote_endpoint, '--serve', SERVICE_DIRECTORY, '--port', '47820']})

    def test_revision_distinguishes_legacy_current_newer_and_invalid(self):
        self.assertEqual(bridge_revision(status()), 0)
        self.assertEqual(bridge_revision(status(BRIDGE_REVISION)), BRIDGE_REVISION)
        self.assertEqual(bridge_revision(status(BRIDGE_REVISION + 1)), BRIDGE_REVISION + 1)
        self.assertIsNone(bridge_revision(status(True)))
        self.assertIsNone(bridge_revision({'service': 'other', 'protocol_version': 2}))

    def test_newer_bridge_is_left_in_place(self):
        with patch('bridgeupdate.wait_for_service', return_value=status(BRIDGE_REVISION + 1)), \
                patch('bridgeupdate.remote') as remote:
            self.assertFalse(update_bridge(self.config, self.token, self.source, None))
        remote.assert_not_called()

    def run_update(self, *, rejects=False, mismatched=False, roothide=False):
        prefix = '/private/preboot/fixture'
        if roothide:
            self.config = replace(self.config, remote_endpoint=prefix + ROOTHIDE_CODE_ROOT + '/fixture/endpoint')
            definition = plistlib.loads(self.daemon)
            definition['ProgramArguments'][0] = self.config.remote_endpoint
            definition['__Patched'] = True
            self.daemon = plistlib.dumps(definition)

        def ssh_command(_config, args, _data=None):
            if args[0] == 'jbroot':
                return (prefix + args[1]).encode()
            if args[0] == 'cat':
                if args[1].endswith('.plist'):
                    return self.daemon
                return (('B' * 24) if mismatched else self.token).encode()
            return b''

        confirmation_error = RemoteSetupError('Fixture refused the new connection') if rejects else None
        capabilities = json.dumps({'bridge_revision': BRIDGE_REVISION, 'required_symbols_available': True})
        environment = {'path_mode': 'roothide' if roothide else 'native'}
        with patch('bridgeupdate.wait_for_service', return_value=status()), \
                patch('bridgeupdate.confirm_revision', side_effect=confirmation_error), \
                patch('bridgeupdate.has_ssh_access', return_value=True), \
                patch('bridgeupdate.bridge_environment', return_value=environment), \
                patch('bridgeupdate.signing_tool', return_value='ldid'), \
                patch('bridgeupdate.require_ios_endpoint'), \
                patch('bridgeupdate.remote_helper', return_value=capabilities) as helper, \
                patch('bridgeupdate.remote', side_effect=ssh_command) as remote, \
                patch('bridgeupdate.RootAccess') as root:
            access = root.return_value
            access.user = 'root'
            if rejects or mismatched:
                with self.assertRaises(RemoteSetupError):
                    update_bridge(self.config, self.token, self.source, None)
            else:
                self.assertTrue(update_bridge(self.config, self.token, self.source, None))
            if roothide:
                self.assertIn(['cat', '/rootfs' + SERVICE_DIRECTORY + '/token'],
                              [call.args[1] for call in remote.call_args_list])
                self.assertEqual(helper.call_args.args[0].path_mode, 'roothide')
                self.assertTrue(helper.call_args.args[1][0].startswith(ROOTHIDE_CODE_ROOT + '/fixture/'))
                signed = next(plistlib.loads(call.args[2]) for call in remote.call_args_list
                              if len(call.args) == 3 and call.args[1][-1].endswith('/endpoint.plist'))
                self.assertTrue(all(signed.get(name) is True for name in ROOTHIDE_ENTITLEMENTS))
        return access.run.call_args_list, [call.args[1][0] for call in remote.call_args_list]

    def test_legacy_bridge_is_replaced_after_verifying_the_staged_build(self):
        root_calls, commands = self.run_update()
        self.assertEqual(len(root_calls), 1)
        self.assertIn('cp -p ', root_calls[0].args[0])
        self.assertIn('ldid', commands)

    def test_failed_version_confirmation_restores_the_previous_executable(self):
        root_calls, _ = self.run_update(rejects=True)
        self.assertEqual(len(root_calls), 2)
        self.assertIn('mv -f ', root_calls[1].args[0])
        self.assertIn('/previous ', root_calls[1].args[0])

    def test_mismatched_ssh_target_is_rejected_before_staging(self):
        root_calls, commands = self.run_update(mismatched=True)
        self.assertEqual(root_calls, [])
        self.assertEqual(commands, ['cat', 'cat'])

    def test_roothide_updates_virtual_files_and_restarts_the_physical_daemon(self):
        root_calls, _ = self.run_update(roothide=True)
        self.assertIn('/private/preboot/fixture/Library/LaunchDaemons/', root_calls[0].args[0])
        self.assertIn('cp -p ' + ROOTHIDE_CODE_ROOT + '/fixture/endpoint ', root_calls[0].args[0])

    def test_confirmation_retries_a_timeout_and_a_stale_reply(self):
        with patch('bridgeupdate.request_json', side_effect=[
            BridgeTimeout(), (200, status()), (200, status(BRIDGE_REVISION))
        ]) as query, patch('bridgeupdate.time.sleep'):
            confirm_revision(self.config, self.token)
        self.assertEqual(query.call_count, 3)
