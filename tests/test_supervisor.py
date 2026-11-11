import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from configuration import load_config
from supervisor import NativeBackend, recovery_gate
from sharingd import ORIGINAL_PLIST, PROGRAM
from state import write_state


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = subprocess.CompletedProcess([], 0,
            'path = /System/Library/LaunchAgents/com.apple.sharingd.plist\n'
            'program = /usr/libexec/sharingd\n', '')

    def test_live_previous_child_prevents_retry(self):
        birth = [123, os.getuid(), 50, 6]
        (self.root / 'backend-children.json').write_text(json.dumps({'broker': birth}))
        with patch('supervisor.process_birth', return_value=tuple(birth)), \
                patch('supervisor.subprocess.run') as command:
            self.assertFalse(recovery_gate(self.root)[0])
            command.assert_not_called()

    def test_pid_reuse_does_not_block_restored_session(self):
        (self.root / 'backend-children.json').write_text(json.dumps({'broker': [123, os.getuid(), 50, 6]}))
        with patch('supervisor.process_birth', return_value=(123, os.getuid(), 70, 8)), \
                patch('supervisor.Path.home', return_value=self.root), \
                patch('supervisor.subprocess.run', return_value=self.original):
            self.assertEqual(recovery_gate(self.root), (True, None))

    def test_uncertain_child_observation_does_not_authorize_restart(self):
        (self.root / 'backend-children.json').write_text(json.dumps({'broker': [123, os.getuid(), 50, 6]}))
        with patch('supervisor.process_birth', side_effect=OSError('observation failed')):
            with self.assertRaises(OSError):
                recovery_gate(self.root)

    def test_custom_or_unobservable_sharingd_defers_retry(self):
        states = [subprocess.CompletedProcess([], 1, '', 'Could not find service'),
                  subprocess.CompletedProcess([], 0, self.original.stdout + 'DYLD_INSERT_LIBRARIES = other', ''),
                  subprocess.CompletedProcess([], 0, self.original.stdout.replace('/System/Library/LaunchAgents/', '/tmp/'), '')]
        for state in states:
            with self.subTest(state=state), patch('supervisor.Path.home', return_value=self.root), \
                    patch('supervisor.subprocess.run', return_value=state):
                self.assertFalse(recovery_gate()[0])

    def test_recovery_error_is_retained_without_spawning_or_repeating_the_same_event(self):
        class Observations:
            count = 0

            def is_set(self):
                return self.count >= 3

            def wait(self, seconds):
                self.count += 1

            def set(self):
                self.count = 3

        backend = NativeBackend(None, self.root, recover=True)
        backend.stop = Observations()
        error = FileNotFoundError(2, 'Missing recorded runtime', '/private/missing-runtime')
        events = []
        with patch('supervisor.SharingdAgent.recover_abandoned', side_effect=error), \
                patch('supervisor.emit_event', side_effect=events.append), \
                patch('supervisor.subprocess.Popen') as spawn:
            backend._run()
            cleanup = backend.close()
            spawn.assert_not_called()
        waiting = [event['NATIVE_BACKEND_STATE'] for event in events
                   if event['NATIVE_BACKEND_STATE']['phase'] == 'waiting_for_cleanup']
        self.assertEqual(len(waiting), 1)
        self.assertEqual(waiting[0]['attempt'], 0)
        self.assertEqual(waiting[0]['observation_error']['error_type'], 'FileNotFoundError')
        self.assertEqual(waiting[0]['observation_error']['errno'], 2)
        self.assertIn('missing-runtime', waiting[0]['observation_error']['error'])
        self.assertFalse(cleanup['cleanup_verified'])
        self.assertEqual(cleanup['cleanup_observation_error']['error_type'], 'FileNotFoundError')


class BackendWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'scripts').mkdir()
        self.run = self.root / 'native-test'
        self.run.mkdir()
        (self.run / 'keystore.dylib').write_bytes(b'test fixture only')
        (self.root / 'config.json').write_text('{}')
        self.config = load_config(self.root / 'config.json', root=self.root)

    def wait_for(self, backend, predicate, seconds=7):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            state = backend.snapshot()
            if predicate(state):
                return state
            time.sleep(.02)
        self.fail('Backend did not reach expected state: ' + repr(backend.snapshot()))

    def test_missing_runtime_is_restored_before_a_real_worker_reaches_readiness(self):
        self.run.chmod(0o700)
        missing = self.root / 'native-20261111-065931/backend-000001'
        cache = self.root / 'Library/Caches/Mirra'
        cache.mkdir(parents=True, mode=0o700)
        write_state(cache / 'sharing.json', {'schema_version': 1,
            'controller_birth': [12345, os.getuid(), 50, 6], 'directory': str(missing),
            'plist_sha256': 'a' * 64})
        owned = (f'gui/{os.getuid()}/com.apple.sharingd = {{\n'
                 f'path = {missing}/sharing.plist\nprogram = {PROGRAM}\n'
                 f'stdout path = {missing}/sharingd.stdout.log\n'
                 f'stderr path = {missing}/sharingd.stderr.log\n'
                 'environment = {\n'
                 f'\tDYLD_INSERT_LIBRARIES => {missing}/keystore.dylib\n'
                 '\tMIRRA_KEYSTORE_BROKER_TOKEN => <redacted>\n}\n}\n')
        original = f'path = {ORIGINAL_PLIST}\nprogram = {PROGRAM}\n'
        state = {'stdout': owned}
        mutations = []

        def command(*arguments, **options):
            if arguments[0] == 'print':
                return subprocess.CompletedProcess([], 0 if state['stdout'] else 113,
                    state['stdout'], '' if state['stdout'] else 'Could not find service')
            mutations.append(arguments)
            if arguments[0] == 'bootout':
                state['stdout'] = ''
            elif arguments[0] == 'bootstrap':
                self.assertEqual(arguments[-1], str(ORIGINAL_PLIST))
                state['stdout'] = original
            else:
                self.fail('Unexpected sharingd mutation: ' + repr(arguments))
            return subprocess.CompletedProcess([], 0, '', '')

        (self.root / 'scripts/backend.py').write_text('''
import json, os, signal, sys, time
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
print(json.dumps({'NATIVE_WORKSPACE_READY': True, 'controller_pid': os.getpid()}), flush=True)
while True:
    time.sleep(.1)
''')
        with patch('supervisor.ROOT', self.root), patch('sharingd.Path.home', return_value=self.root), \
                patch('sharingd.process_birth', return_value=None), \
                patch('sharingd.launchctl', side_effect=command), patch('supervisor.emit_event'):
            backend = NativeBackend(self.config, self.run, recover=True).start()
            try:
                ready = self.wait_for(backend, lambda state: state['ready'])
                self.assertEqual(ready['attempt'], 1)
                self.assertIsNone(backend.process.poll())
                self.assertFalse((cache / 'sharing.json').exists())
                self.assertFalse(missing.exists())
                self.assertEqual([args[0] for args in mutations], ['bootout', 'bootstrap'])
            finally:
                closed = backend.close()
        self.assertTrue(closed['cleanup_verified'])
        self.assertIsNone(closed['cleanup_error'])

    def test_terminal_worker_retries_and_new_worker_can_stop(self):
        # A real pipe/process exercises readiness delivery and EOF, rather than
        # mocking Popen.poll to mirror the supervisor state machine.
        (self.root / 'scripts/backend.py').write_text('''
import json, os, pathlib, signal, sys, time
config = pathlib.Path(sys.argv[sys.argv.index('--config') + 1])
attempt = int(config.parent.name.split('-')[-1])
print(json.dumps({'NATIVE_WORKSPACE_READY': True, 'controller_pid': os.getpid()}), flush=True)
if attempt == 1:
    time.sleep(.1)
    sys.exit(7)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    time.sleep(.1)
''')
        with patch('supervisor.ROOT', self.root), \
                patch('supervisor.recovery_gate', return_value=(True, None)), \
                patch('supervisor.SharingdAgent.recover_abandoned', return_value=None), \
                patch('supervisor.emit_event'):
            backend = NativeBackend(self.config, self.run, recover=True).start()
            try:
                ready = self.wait_for(backend, lambda s: s['attempt'] == 2 and s['ready'])
                self.assertIsNone(backend.process.poll())
                persisted = json.loads((self.run / 'backend-status.json').read_text())
                self.assertEqual(persisted['worker_pid'], ready['worker_pid'])
                self.assertTrue((self.run / 'backend-000001/backend.log').read_text().strip())
            finally:
                report = backend.close()
            self.assertTrue(report['cleanup_verified'])
            self.assertIsNone(report['cleanup_error'])
            self.assertEqual(report['exit_code'], 0)

    def test_failed_observation_waits_without_starting_a_worker(self):
        with patch('supervisor.recovery_gate', side_effect=subprocess.TimeoutExpired('launchctl', 5)), \
                patch('supervisor.SharingdAgent.recover_abandoned', return_value=None), \
                patch('supervisor.subprocess.Popen') as spawn, patch('supervisor.emit_event'):
            backend = NativeBackend(self.config, self.run, recover=True).start()
            try:
                self.wait_for(backend, lambda s: s['phase'] == 'waiting_for_cleanup')
                spawn.assert_not_called()
            finally:
                backend.close()


if __name__ == '__main__':
    unittest.main()
