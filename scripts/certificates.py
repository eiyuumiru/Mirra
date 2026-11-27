"""Use a current certificate from the enrolled bridge without changing its saved profile."""
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from bridgeclient import read_token, request
from provisioning import certificate_from_service, RemoteSetupError
from state import write_state

RETRY_SECONDS = 900
# The issuer answered but kept the same expired certificate (seen on jailbroken
# bridges whose activation service does not mint a new one). Asking again costs
# each startup ~12s on the bridge, so wait longer; Renew Now still forces it.
UNCHANGED_RETRY_SECONDS = 12 * 3600


class CertificateError(RuntimeError):
    def __init__(self, code, message, retry_at=None):
        super().__init__(message)
        self.code = code
        self.retry_at = retry_at


def validity(data):
    if not 0 < len(data) <= 1_048_576:
        raise CertificateError('invalid', 'The bridge certificate has an invalid size')
    try:
        result = subprocess.run(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-noout', '-startdate', '-enddate'],
                                input=data, capture_output=True, check=True, timeout=5,
                                env={**os.environ, 'LC_ALL': 'C'})
        dates = dict(line.split('=', 1) for line in result.stdout.decode('ascii').splitlines())
        start, end = (datetime.strptime(dates[key], '%b %d %H:%M:%S %Y %Z')
                      .replace(tzinfo=timezone.utc).timestamp() for key in ('notBefore', 'notAfter'))
        if end <= start:
            raise ValueError('Invalid certificate date range')
        return start, end
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        raise CertificateError('invalid', 'Could not check the bridge certificate dates') from error


def current_certificate(config, renewal_state, on_renewal, *, force=False):
    """Return certificate bytes, validity window and whether the enrolled file differs."""
    installed = config.certificate_file.read_bytes()
    installed_start, installed_end = validity(installed)
    now = time.time()
    if installed_start > now:
        raise CertificateError('clock', 'The saved certificate is not yet valid. Check the Mac’s clock.')
    if installed_end > now:
        return installed, installed_start, installed_end, False

    renewal_state = Path(renewal_state)
    directory = renewal_state.parent
    directory.mkdir(exist_ok=True, mode=0o700)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CertificateError('invalid', 'Certificate renewal requires a private Mirra runtime directory')
    try:
        descriptor = os.open(directory / 'certificate-renewal.lock',
                             os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    except OSError as error:
        if error.errno != errno.ELOOP:
            raise
        raise CertificateError('invalid', 'Certificate renewal lock is not a private Mirra file') from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CertificateError('invalid', 'Certificate renewal lock is not a private Mirra file')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CertificateError('busy', 'A bridge certificate check or renewal is already in progress.') from error
        return _check_bridge(config, renewal_state, on_renewal, force=force)
    finally:
        os.close(descriptor)


def _check_bridge(config, renewal_state, on_renewal, *, force):
    # The installed file anchors enrollment. Use replacements only from the
    # same TLS-authenticated bridge, without changing the saved profile.
    try:
        token = read_token(config.token_file)
        status, _, data = request(config, token, 'GET', '/v1/certificate', timeout=10)
    except OSError as error:
        raise CertificateError('unavailable', 'Mirra could not reach the enrolled bridge to check its certificate') from error
    if status != 200:
        raise CertificateError('unavailable', 'The enrolled bridge did not return its certificate')
    start, end = validity(data)
    now = time.time()
    if start > now:
        raise CertificateError('clock', 'The bridge certificate is not yet valid. Check the Mac’s clock.')
    if end > now:
        return data, start, end, True

    try:
        info = renewal_state.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CertificateError('invalid', 'Certificate retry state is not a private Mirra file')
        try:
            state = json.loads(renewal_state.read_text())
        except (ValueError, UnicodeError) as error:
            raise CertificateError('invalid', 'Certificate retry state is invalid') from error
        if not isinstance(state, dict):
            raise CertificateError('invalid', 'Certificate retry state is invalid')
        retry_at = state.get('retry_at')
        if (not force and type(retry_at) in (int, float)
                and now < retry_at <= now + max(RETRY_SECONDS, UNCHANGED_RETRY_SECONDS)):
            raise CertificateError('expired', 'The bridge still has an expired certificate', retry_at)
    retry_at = now + RETRY_SECONDS
    # Record the cooldown before asking the issuer, even if the process is interrupted.
    write_state(renewal_state, {'retry_at': retry_at})
    on_renewal()
    try:
        data, _ = certificate_from_service(config, token, issue=True, issue_if_missing=False,
                                           replace_expired_sha256=hashlib.sha256(data).hexdigest())
        start, end = validity(data)
    except RemoteSetupError as error:
        if error.code == 'certificate_unchanged':
            retry_at = now + UNCHANGED_RETRY_SECONDS
            write_state(renewal_state, {'retry_at': retry_at})
            raise CertificateError('expired', 'The iPhone still returns the same expired certificate after requesting renewal',
                                   retry_at) from error
        raise CertificateError('expired', 'The bridge could not renew its certificate', retry_at) from error
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise CertificateError('expired', 'The bridge could not renew its certificate', retry_at) from error
    if not start <= time.time() < end:
        raise CertificateError('expired', 'The issuer did not return a currently valid certificate', retry_at)
    return data, start, end, True
