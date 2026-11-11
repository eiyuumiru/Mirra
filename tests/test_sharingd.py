import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from sharingd import SharingdAgent, ORIGINAL_PLIST, PROGRAM, service
from state import write_state


class SharingdRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / 'backend-000001'
        self.directory.mkdir(mode=0o700)
        self.plist = self.directory / 'sharing.plist'
        self.plist.write_bytes(b'owned test configuration')
        self.plist.chmod(0o600)
        self.patch_home = patch('sharingd.Path.home', return_value=self.root)
        self.patch_home.start()
        self.addCleanup(self.patch_home.stop)
        self.agent = SharingdAgent(self.directory)
        self.agent.cache.mkdir(parents=True, mode=0o700)
        self.birth = [12345, os.getuid(), 50, 6]
        self.record = {'schema_version': 1, 'controller_birth': self.birth,
            'directory': str(self.directory), 'plist_sha256': hashlib.sha256(self.plist.read_bytes()).hexdigest()}
        write_state(self.agent.journal, self.record)
        self.original = {'program': PROGRAM, 'path': str(ORIGINAL_PLIST), 'injected': False}
        self.owned = {'program': PROGRAM, 'path': str(self.plist), 'injected': True}
        self.owned.update(environment={'DYLD_INSERT_LIBRARIES': str(self.directory / 'keystore.dylib')},
                          **{'stdout path': str(self.directory / 'sharingd.stdout.log'),
                             'stderr path': str(self.directory / 'sharingd.stderr.log')})
        self.success = subprocess.CompletedProcess([], 0, '', '')

    def test_dead_controller_restores_owned_job_and_clears_journal(self):
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[self.owned, {}, self.original]), \
                patch('sharingd.launchctl', return_value=self.success) as command:
            result = SharingdAgent.recover_abandoned()
        self.assertTrue(result['original_restored'])
        self.assertEqual([c.args[0] for c in command.call_args_list], ['bootout', 'bootstrap'])
        self.assertFalse(self.agent.journal.exists())
        self.assertEqual(json.loads((self.directory / 'sharingd-last-restore.json').read_text()), self.original)

    def test_live_controller_is_not_recovered_even_if_lock_is_free(self):
        with patch('sharingd.process_birth', return_value=tuple(self.birth)), \
                patch('sharingd.launchctl') as command:
            with self.assertRaisesRegex(RuntimeError, 'still running'):
                SharingdAgent.recover_abandoned()
            command.assert_not_called()
        self.assertTrue(self.agent.journal.exists())

    def test_identity_observation_failure_is_not_death(self):
        with patch('sharingd.process_birth', side_effect=OSError('not observable')), \
                patch('sharingd.launchctl') as command:
            with self.assertRaises(OSError):
                SharingdAgent.recover_abandoned()
            command.assert_not_called()

    def test_changed_job_or_plist_is_not_unloaded(self):
        foreign = dict(self.owned, path='/another/agent.plist')
        for state, change in [(foreign, False), (self.owned, True)]:
            with self.subTest(change=change):
                if change:
                    self.plist.write_bytes(b'changed')
                with patch('sharingd.process_birth', return_value=None), \
                        patch('sharingd.service', return_value=state), \
                        patch('sharingd.launchctl') as command:
                    with self.assertRaises(RuntimeError):
                        SharingdAgent.recover_abandoned()
                    command.assert_not_called()
                self.assertTrue(self.agent.journal.exists())

    def test_partial_restore_retries_from_missing_job_without_second_bootout(self):
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[{}, self.original]), \
                patch('sharingd.launchctl', return_value=self.success) as command:
            self.assertTrue(SharingdAgent.recover_abandoned()['original_restored'])
            self.assertEqual([c.args[0] for c in command.call_args_list], ['bootstrap'])

    def test_observation_error_does_not_look_like_missing_service(self):
        failed = subprocess.CompletedProcess([], 1, '', 'Operation not permitted')
        with patch('sharingd.launchctl', return_value=failed):
            with self.assertRaises(RuntimeError):
                service()

    def test_missing_runtime_is_recovered_without_recreating_the_directory(self):
        shutil.rmtree(self.directory)
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[self.owned, {}, self.original]), \
                patch('sharingd.launchctl', return_value=self.success) as command:
            result = SharingdAgent.recover_abandoned()
        self.assertTrue(result['original_restored'])
        self.assertEqual([c.args[0] for c in command.call_args_list], ['bootout', 'bootstrap'])
        self.assertFalse(self.agent.journal.exists())
        self.assertFalse(self.directory.exists())
        saved = json.loads((self.agent.cache / 'sharingd-last-restore.json').read_text())
        self.assertEqual(saved['directory'], str(self.directory))
        self.assertEqual(saved['state'], self.original)

    def test_missing_plist_requires_the_live_job_to_match_the_mirra_adapter(self):
        self.plist.unlink()
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[self.owned, {}, self.original]), \
                patch('sharingd.launchctl', return_value=self.success):
            self.assertTrue(SharingdAgent.recover_abandoned()['original_restored'])
        self.assertFalse(self.agent.journal.exists())
        self.assertEqual(json.loads((self.directory / 'sharingd-last-restore.json').read_text()), self.original)

    def test_missing_runtime_does_not_make_a_live_controller_abandoned(self):
        shutil.rmtree(self.directory)
        with patch('sharingd.process_birth', return_value=tuple(self.birth)), \
                patch('sharingd.launchctl') as command:
            with self.assertRaisesRegex(RuntimeError, 'still running'):
                SharingdAgent.recover_abandoned()
            command.assert_not_called()
        self.assertTrue(self.agent.journal.exists())

    def test_original_job_with_missing_runtime_can_retire_its_old_journal(self):
        shutil.rmtree(self.directory)
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', return_value=self.original), \
                patch('sharingd.launchctl') as command:
            self.assertTrue(SharingdAgent.recover_abandoned()['original_restored'])
            command.assert_not_called()
        self.assertFalse(self.agent.journal.exists())
        self.assertFalse(self.directory.exists())

    def test_missing_job_and_runtime_can_restore_the_original_job(self):
        shutil.rmtree(self.directory)
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[{}, self.original]), \
                patch('sharingd.launchctl', return_value=self.success) as command:
            self.assertTrue(SharingdAgent.recover_abandoned()['original_restored'])
        self.assertEqual([c.args[0] for c in command.call_args_list], ['bootstrap'])
        self.assertFalse(self.directory.exists())

    def test_missing_runtime_preserves_changed_or_unrecognized_jobs(self):
        shutil.rmtree(self.directory)
        states = [dict(self.owned, path='/another/sharing.plist'),
                  dict(self.owned, program='/another/sharingd'),
                  dict(self.owned, environment={}),
                  dict(self.owned, environment={'DYLD_INSERT_LIBRARIES': '/another/keystore.dylib'}),
                  dict(self.owned, environment={'DYLD_INSERT_LIBRARIES':
                       str(self.directory / 'keystore.dylib') + ':/another/adapter.dylib'}),
                  dict(self.owned, **{'stderr path': '/another/log'})]
        for current in states:
            with self.subTest(current=current), patch('sharingd.process_birth', return_value=None), \
                    patch('sharingd.service', return_value=current), patch('sharingd.launchctl') as command:
                with self.assertRaises(RuntimeError):
                    SharingdAgent.recover_abandoned()
                command.assert_not_called()
                self.assertTrue(self.agent.journal.exists())

    def test_missing_runtime_keeps_the_journal_until_restoration_is_verified(self):
        shutil.rmtree(self.directory)
        with patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.service', side_effect=[self.owned, {}, {}]), \
                patch('sharingd.launchctl', return_value=self.success):
            with self.assertRaisesRegex(RuntimeError, 'not verified'):
                SharingdAgent.recover_abandoned()
        self.assertTrue(self.agent.journal.exists())

    def test_missing_runtime_requires_a_private_owned_ancestor(self):
        shutil.rmtree(self.directory)
        self.root.chmod(0o755)
        self.addCleanup(self.root.chmod, 0o700)
        with patch('sharingd.process_birth', return_value=None), patch('sharingd.launchctl') as command:
            with self.assertRaisesRegex(RuntimeError, 'not private'):
                SharingdAgent.recover_abandoned()
            command.assert_not_called()
        self.assertTrue(self.agent.journal.exists())

    def test_job_environment_is_read_from_the_explicit_registration(self):
        stdout = (f'path = {self.plist}\nprogram = {PROGRAM}\n'
                  f'stdout path = {self.directory}/sharingd.stdout.log\n'
                  f'stderr path = {self.directory}/sharingd.stderr.log\n'
                  'inherited environment = {\n'
                  '\tDYLD_INSERT_LIBRARIES => /unrelated/inherited.dylib\n}\n'
                  'environment = {\n'
                  f'\tDYLD_INSERT_LIBRARIES => {self.directory}/keystore.dylib\n'
                  '\tMIRRA_KEYSTORE_BROKER_TOKEN => private-test-token\n}\n')
        with patch('sharingd.launchctl', return_value=subprocess.CompletedProcess([], 0, stdout, '')):
            observed = service()
        self.assertEqual(observed['environment'], {'DYLD_INSERT_LIBRARIES': str(self.directory / 'keystore.dylib')})
        self.assertNotIn('private-test-token', json.dumps(observed))
        self.assertEqual(observed['stdout path'], str(self.directory / 'sharingd.stdout.log'))


if __name__ == '__main__':
    unittest.main()
