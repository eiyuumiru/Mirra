import json
from datetime import date, timedelta
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from diagnostics import collect, hardware_snapshot, PrivateReader, project_line, MAX_ENTRIES, MAX_MESSAGE
from logstream import project, predicate, NOISY_FRAMEWORKS
from activity import FileLog


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.run = self.root/'current/runtime/native-20261108-110000'
        self.write('service.json', {'directory':str(self.run),'phase':'running'})
        self.write('current/runtime/native-20261108-110000/backend-status.json',
                   {'phase':'ready','attempt':1,'ready':True,'directory':'backend-000001'})

    def file(self, name, data):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in path.parents:
            if parent == self.root.parent:
                break
            parent.chmod(0o700)
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def write(self, name, value):
        return self.file(name, json.dumps(value).encode())

    def test_hardware_snapshot_is_explicit_persisted_and_does_not_reset_log_cursor(self):
        report = {'schema_version': 1, 'wifi': {'status': 'unknown', 'reason': 'timeout'},
                  'native_mirroring_verified': None}
        with patch('hardware.inspect_host_environment', return_value=report) as inspect:
            collect(self.root)
            inspect.assert_not_called()
            snapshot = hardware_snapshot(self.root)
            inspect.assert_called_once_with()
        self.assertNotIn('cursor', snapshot)
        self.assertTrue(snapshot['ok'])
        messages = [json.loads(item['message']) for item in snapshot['entries']]
        self.assertIn({'wifi': report['wifi']}, messages)
        files = list((self.root/'logs').glob('native-*.log'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        saved = [json.loads(line) for line in files[0].read_text().splitlines()]
        self.assertEqual([row['message'] for row in saved], [row['message'] for row in snapshot['entries']])

    def test_large_hardware_lists_remain_complete_json_without_truncation(self):
        drivers = [{'bundle_identifier': 'example.' + 'x'*100 + str(i), 'loaded_version': '1.2'} for i in range(128)]
        names = ['GPU ' + '\U0001f600'*200 for _ in range(16)]
        with patch('hardware.inspect_host_environment', return_value={'loaded_drivers': {'entries': drivers}, 'gpu_names': names}):
            snapshot = hardware_snapshot(self.root)
        recovered = []
        recovered_names = []
        for item in snapshot['entries']:
            self.assertLessEqual(len(item['message']), MAX_MESSAGE)
            self.assertLessEqual(len(item['message'].encode('utf-16-le')) // 2, MAX_MESSAGE)
            decoded = json.loads(item['message'])
            for key, value in decoded.items():
                if isinstance(value, list):
                    (recovered_names if key.startswith('gpu_names') else recovered).extend(value)
        self.assertEqual(recovered, drivers)
        self.assertEqual(recovered_names, names)
        self.assertLess(len(snapshot['entries']), 160)

    def test_hardware_storage_failure_preserves_snapshot_without_exposing_error_paths(self):
        (self.root/'logs').symlink_to(self.root)
        with patch('hardware.inspect_host_environment', return_value={'wifi': {'status': 'unknown'}}):
            snapshot = hardware_snapshot(self.root)
        self.assertTrue(snapshot['ok'])
        self.assertTrue(any(item['level'] == 'warning' for item in snapshot['entries']))
        self.assertNotIn(str(self.root), json.dumps(snapshot))

    def test_decoder_state_distinguishes_ready_hook_from_unknown_frame_delivery(self):
        video = {'session_created': True, 'creation_status': 0,
                 'frame_delivery_verified': None, 'presentation_verified': None}
        self.write('current/runtime/native-20261108-110000/decoder-route.json', {
            'mode': 'no_fls', 'ready': True, 'native_video_observations': video,
            'stage': 'private-path', 'native_decoder_events': ['private-event']})
        snapshot = collect(self.root)
        row = next(row for row in snapshot['entries'] if row['source'] == 'Decoder')
        self.assertEqual(json.loads(row['message'])['native_video_observations'], video)
        self.assertNotIn('private', row['message'])
        self.assertFalse(any(row['source'] == 'Decoder' for row in collect(self.root, snapshot['cursor'])['entries']))

    def test_live_setup_output_is_read_without_repeating_unchanged_lines(self):
        path = self.file('logs/setup.log', b'{"source":"SSH stderr","message":"debug1: Authentication succeeded (publickey).","timestamp":"2026-11-08T04:00:00.000000+00:00","level":"debug"}\n')
        first = collect(self.root)
        self.assertTrue(any('Authentication succeeded (publickey).' in e['message'] for e in first['entries']))
        self.assertEqual(collect(self.root, first['cursor'])['entries'], [])
        with path.open('ab') as output:
            output.write(b'{"source":"Certificate","message":"--issue-certificate begin","fields":{"path":"/var/mobile/certificate.der"}}\n')
        second = collect(self.root, first['cursor'])
        self.assertEqual(len(second['entries']), 1)
        self.assertIn('/var/mobile/certificate.der', second['entries'][0]['message'])

    def test_unknown_device_errors_are_preserved_instead_of_mapped_to_constants(self):
        message = 'RuntimeError: A11 custom failure 0xe00002bc; aks_new_function unavailable'
        rows = project_line(message.encode(), 'SSH')
        self.assertEqual(rows[0]['message'], message)
        self.assertNotIn('Check the phone', rows[0]['message'])

    def test_recent_timestamped_setup_output_is_retained_over_old_undated_tails(self):
        self.file('logs/setup.log', b'{"source":"SSH stderr","message":"real current SSH result","timestamp":"2026-11-08T04:00:00.000000+00:00"}\n')
        self.file('logs/service.log', b''.join(f'old undated line {i}\n'.encode() for i in range(300)))
        result = collect(self.root)
        self.assertTrue(any(e['message'] == 'real current SSH result' for e in result['entries']))
        self.assertLessEqual(len(result['entries']), MAX_ENTRIES)

    def test_partial_line_waits_and_copy_truncate_regrowth_is_detected(self):
        path = self.file('logs/setup.log', b'first real line\npartial')
        first = collect(self.root)
        self.assertTrue(any(e['message'] == 'first real line' for e in first['entries']))
        self.assertFalse(any(e['message'] == 'partial' for e in first['entries']))
        with path.open('ab') as output:
            output.write(b' finished\n')
        second = collect(self.root, first['cursor'])
        self.assertEqual(second['entries'][0]['message'], 'partial finished')
        path.write_bytes(b'new after rotation, longer than the old offset\n')
        third = collect(self.root, second['cursor'])
        self.assertEqual(third['entries'][0]['message'], 'new after rotation, longer than the old offset')

    def test_symlink_and_nonprivate_logs_are_not_followed(self):
        outside = self.root/'private-target'; outside.write_text('not a log secret')
        logs = self.root/'logs'; logs.mkdir(mode=0o700)
        (logs/'setup.log').symlink_to(outside)
        result = collect(self.root)
        self.assertNotIn('not a log secret', json.dumps(result))
        self.assertTrue(any(e['source'] == 'Logs' for e in result['entries']))
        (logs/'setup.log').unlink()
        path = logs/'setup.log'; path.write_text('public mode secret\n'); path.chmod(0o644)
        self.assertNotIn('public mode secret', json.dumps(collect(self.root)))

    def test_arbitrary_runtime_path_and_cursor_do_not_authorize_reads(self):
        outside = self.root/'outside'
        self.write('service.json', {'directory':str(outside/'native-20261108-110000')})
        self.file('outside/native-20261108-110000/app.log', b'outside secret\n')
        result = collect(self.root, {'files':{'../../private':{'offset':0}}})
        self.assertNotIn('outside secret', json.dumps(result))
        self.assertNotIn('../../private', json.dumps(result['cursor']))

    def test_tail_is_bounded_and_never_changes_protocol_or_state(self):
        path = self.file('logs/setup.log', b''.join(f'actual line {i}\n'.encode() for i in range(5000)))
        before = path.read_bytes()
        states = (self.root/'service.json').read_bytes()
        result = collect(self.root)
        self.assertLessEqual(len(result['entries']), MAX_ENTRIES)
        self.assertTrue(any('actual line 4999' in e['message'] for e in result['entries']))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual((self.root/'service.json').read_bytes(), states)

    def test_native_mirroring_message_keeps_real_text_and_masks_tokens(self):
        value = {'eventMessage':'Connection failed with error 42 token=private-token',
                 'messageType':'Error','processID':123,'subsystem':'com.apple.ScreenContinuity',
                 'category':'connection','timestamp':'2026-11-08 11:00:00.123+0700'}
        row = project(json.dumps(value).encode())
        self.assertIn('Connection failed with error 42', row['message'])
        self.assertIn('pid=123', row['message'])
        self.assertNotIn('private-token', row['message'])
        self.assertEqual(row['level'], 'error')

    def test_short_credentials_in_json_do_not_enter_the_viewer(self):
        path = self.file('logs/setup.log', b'{"operation":"generate","status":0,"data":"small-secret","_auth":"auth-secret"}\n')
        text = json.dumps(collect(self.root))
        self.assertNotIn('small-secret', text)
        self.assertNotIn('auth-secret', text)
        self.assertIn('generate', text)

    def test_verbose_hides_only_routine_framework_debug_messages(self):
        for subsystem in NOISY_FRAMEWORKS:
            value = {'eventMessage':'actual framework event','messageType':'Debug','subsystem':subsystem}
            self.assertIsNone(project(json.dumps(value)))
            self.assertIn('actual framework event', project(json.dumps(value), verbose=True)['message'])
            value['messageType'] = 'Error'
            self.assertEqual(project(json.dumps(value))['level'], 'error')
        value = {'eventMessage':'actual connection negotiation','messageType':'Debug','subsystem':'com.apple.ScreenContinuity'}
        self.assertIn('actual connection negotiation', project(json.dumps(value))['message'])
        self.assertIn('logType == "debug"', predicate())
        self.assertNotIn('logType == "debug"', predicate(verbose=True))

    def test_dated_files_are_followed_across_midnight_without_repeating_output(self):
        today=date.today();day=[today-timedelta(days=1)]
        log=FileLog(self.root/'logs',clock=lambda:day[0])
        log({'source':'SSH stderr','message':'real SSH output before midnight'})
        first=collect(self.root)
        self.assertTrue(any(e['message']=='real SSH output before midnight' for e in first['entries']))
        day[0]=today
        log({'source':'SSH stderr','message':'real SSH output after midnight'})
        second=collect(self.root,first['cursor'])
        self.assertEqual([e['message'] for e in second['entries']],['real SSH output after midnight'])
        self.assertEqual(collect(self.root,second['cursor'])['entries'],[])
