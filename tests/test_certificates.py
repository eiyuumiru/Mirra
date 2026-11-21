import fcntl
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from certificates import CertificateError, RETRY_SECONDS, UNCHANGED_RETRY_SECONDS, current_certificate
from provisioning import RemoteSetupError


class BridgeCertificateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        installed = root / 'installed.der'
        installed.write_bytes(b'installed')
        self.config = SimpleNamespace(certificate_file=installed, token_file=root / 'token')
        self.state = root / 'retry.json'
        self.started = Mock()
        windows = {b'installed': (1, 50), b'expired': (2, 60), b'valid': (80, 140)}
        for name, kwargs in (
            ('time.time', {'return_value': 100}),
            ('validity', {'side_effect': windows.__getitem__}),
            ('read_token', {'return_value': 'fixture'}),
            ('request', {'return_value': (200, '', b'expired')}),
            ('certificate_from_service', {'return_value': (b'valid', True)}),
        ):
            context = patch('certificates.' + name, **kwargs)
            setattr(self, name.rsplit('.', 1)[-1], context.start())
            self.addCleanup(context.stop)

    def read(self):
        return current_certificate(self.config, self.state, self.started)

    def test_valid_enrollment_requires_no_bridge_request(self):
        self.config.certificate_file.write_bytes(b'valid')
        self.assertEqual(self.read(), (b'valid', 80, 140, False))
        self.request.assert_not_called()
        self.certificate_from_service.assert_not_called()

    def test_existing_valid_replacement_is_reused_even_in_cooldown(self):
        self.state.write_text(json.dumps({'retry_at': 800}))
        self.state.chmod(0o600)
        self.request.return_value = (200, '', b'valid')
        self.assertEqual(self.read(), (b'valid', 80, 140, True))
        self.certificate_from_service.assert_not_called()
        self.assertEqual(self.config.certificate_file.read_bytes(), b'installed')

    def test_expired_certificate_is_renewed_using_the_enrolled_bridge(self):
        self.assertEqual(self.read(), (b'valid', 80, 140, True))
        self.started.assert_called_once()
        self.certificate_from_service.assert_called_once_with(self.config, 'fixture', issue=True, issue_if_missing=False,
            replace_expired_sha256=hashlib.sha256(b'expired').hexdigest())

    def test_expired_issuer_reply_is_rejected_and_not_requested_again_during_cooldown(self):
        self.certificate_from_service.return_value = (b'expired', True)
        for _ in range(2):
            with self.assertRaises(CertificateError) as error:
                self.read()
            self.assertEqual(error.exception.code, 'expired')
            self.assertEqual(error.exception.retry_at, 100 + RETRY_SECONDS)
        self.certificate_from_service.assert_called_once()
        self.assertEqual(self.config.certificate_file.read_bytes(), b'installed')

    def test_manual_renewal_bypasses_and_resets_the_cooldown(self):
        self.state.write_text(json.dumps({'retry_at': 800}))
        self.state.chmod(0o600)
        with self.assertRaises(CertificateError):
            self.read()
        self.certificate_from_service.assert_not_called()

        self.assertEqual(current_certificate(self.config, self.state, self.started, force=True),
                         (b'valid', 80, 140, True))
        self.certificate_from_service.assert_called_once()
        self.assertEqual(json.loads(self.state.read_text())['retry_at'], 100 + RETRY_SECONDS)

    def test_manual_renewal_reuses_a_valid_bridge_certificate(self):
        self.request.return_value = (200, '', b'valid')
        self.assertEqual(current_certificate(self.config, self.state, self.started, force=True),
                         (b'valid', 80, 140, True))
        self.certificate_from_service.assert_not_called()

    def test_auto_and_manual_checks_share_the_same_lock(self):
        lock = self.state.parent / 'certificate-renewal.lock'
        lock.touch(mode=0o600)
        with lock.open('r+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for force in (False, True):
                with self.assertRaises(CertificateError) as error:
                    current_certificate(self.config, self.state, self.started, force=force)
                self.assertEqual(error.exception.code, 'busy')
        self.request.assert_not_called()
        self.certificate_from_service.assert_not_called()

    def test_unchanged_expired_certificate_reports_the_issuer_outcome(self):
        self.certificate_from_service.side_effect = RemoteSetupError('Fixture', 'certificate_unchanged')
        with self.assertRaisesRegex(CertificateError, 'same expired certificate') as error:
            current_certificate(self.config, self.state, self.started, force=True)
        self.assertEqual(error.exception.code, 'expired')
        self.assertEqual(error.exception.retry_at, 100 + UNCHANGED_RETRY_SECONDS)
        # The longer cooldown also holds for later automatic checks.
        self.certificate_from_service.reset_mock()
        with self.assertRaises(CertificateError):
            self.read()
        self.certificate_from_service.assert_not_called()

    def test_future_certificate_stops_without_asking_for_issuance(self):
        self.time.return_value = 0
        with self.assertRaises(CertificateError) as error:
            self.read()
        self.assertEqual(error.exception.code, 'clock')
        self.certificate_from_service.assert_not_called()


if __name__ == '__main__':
    unittest.main()
