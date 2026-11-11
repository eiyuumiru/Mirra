"""Exclusive, journaled ownership of the temporary sharingd launch agent."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

from processes import process_birth
from state import write_state

ORIGINAL_PLIST = Path('/System/Library/LaunchAgents/com.apple.sharingd.plist')
PROGRAM = '/usr/libexec/sharingd'


def launchctl(*arguments, timeout=15):
    return subprocess.run(['launchctl', *arguments], capture_output=True, text=True, timeout=timeout)


def service(target=None, *, timeout=15):
    reply = launchctl('print', target or f'gui/{os.getuid()}/com.apple.sharingd', timeout=timeout)
    if reply.returncode:
        if 'Could not find service' in reply.stderr:
            return {}
        raise RuntimeError('Cannot inspect sharingd registration: ' + reply.stderr.strip())
    values = {'injected': 'DYLD_INSERT_LIBRARIES' in reply.stdout or 'MIRRA_KEYSTORE' in reply.stdout,
              'environment': {}}
    environment = False
    for line in reply.stdout.splitlines():
        line = line.strip()
        if line == 'environment = {':
            environment = True
        elif line == '}':
            environment = False
        elif environment:
            key, separator, value = line.partition(' => ')
            if separator and key == 'DYLD_INSERT_LIBRARIES':
                values['environment'][key] = value
        key, separator, value = line.partition(' = ')
        if separator and key in {'program', 'path', 'pid', 'state', 'last exit code',
                                 'stdout path', 'stderr path'}:
            values.setdefault(key, value)
    return values


def is_original(state):
    return (state.get('program') == PROGRAM and state.get('path') == str(ORIGINAL_PLIST)
            and not state.get('injected'))


def _private_directory(directory):
    """Validate the directory or its nearest remaining ancestor; never recreate it."""
    parent = directory
    while True:
        try:
            info = parent.lstat()
            break
        except FileNotFoundError:
            parent = parent.parent
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('sharingd ownership directory is not private')
    return parent == directory


class SharingdAgent:
    def __init__(self, directory=None):
        self.directory = Path(directory).resolve() if directory is not None else None
        self.domain = f'gui/{os.getuid()}'
        self.target = self.domain + '/com.apple.sharingd'
        self.cache = Path.home() / 'Library/Caches/Mirra'
        self.journal = self.cache / 'sharing.json'
        self.lock = None
        self.owned = False

    def acquire(self):
        self.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = (self.cache / 'sharingd-agent.lock').open('a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.lock.close()
            self.lock = None
            raise

    def read_journal(self):
        try:
            info = self.journal.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('sharingd ownership journal is not a private owned file')
        record = json.loads(self.journal.read_text())
        if not isinstance(record, dict) or record.get('schema_version') != 1:
            raise RuntimeError('Invalid sharingd ownership journal')
        birth = record.get('controller_birth')
        if (not isinstance(birth, list) or len(birth) != 4 or any(type(n) is not int for n in birth)
                or birth[0] <= 0 or birth[1] != os.getuid()):
            raise RuntimeError('Invalid sharingd controller identity')
        if not isinstance(record.get('directory'), str):
            raise RuntimeError('Invalid sharingd ownership directory')
        directory = Path(record['directory'])
        if not directory.is_absolute() or directory.resolve() != directory:
            raise RuntimeError('Invalid sharingd ownership directory')
        _private_directory(directory)
        if (not isinstance(record.get('plist_sha256'), str)
                or re.fullmatch('[0-9a-f]{64}', record['plist_sha256']) is None):
            raise RuntimeError('Invalid sharingd launch configuration digest')
        return record

    def _verify_owned_job(self, current, directory, digest):
        plist = directory / 'sharing.plist'
        try:
            info = plist.lstat()
        except FileNotFoundError:
            # launchd retains a loaded definition even if its source folder was
            # removed. The private journal and the job's exact adapter/log paths
            # must agree before an abandoned registration may be unloaded.
            if (current.get('injected') is not True
                    or current.get('environment', {}).get('DYLD_INSERT_LIBRARIES')
                       != str(directory / 'keystore.dylib')
                    or current.get('stdout path') != str(directory / 'sharingd.stdout.log')
                    or current.get('stderr path') != str(directory / 'sharingd.stderr.log')):
                raise RuntimeError('Missing sharingd configuration cannot be verified; recovery deferred')
        else:
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or hashlib.sha256(plist.read_bytes()).hexdigest() != digest):
                raise RuntimeError('Owned sharingd configuration changed; recovery deferred')

    def _restore(self, record):
        directory = Path(record['directory'])
        plist = directory / 'sharing.plist'
        current = service(self.target)
        if current.get('path') == str(plist) and current.get('program') == PROGRAM:
            self._verify_owned_job(current, directory, record['plist_sha256'])
            reply = launchctl('bootout', self.target)
            if reply.returncode:
                raise RuntimeError('Cannot unload owned sharingd: ' + reply.stderr.strip())
            current = service(self.target)
        elif current and not is_original(current):
            raise RuntimeError('sharingd ownership changed; refusing to replace another configuration')
        if not current:
            reply = launchctl('bootstrap', self.domain, str(ORIGINAL_PLIST))
            if reply.returncode:
                raise RuntimeError('Cannot restore original sharingd: ' + reply.stderr.strip())
        restored = service(self.target)
        if not is_original(restored):
            raise RuntimeError('Original sharingd restoration is not verified')
        if _private_directory(directory):
            write_state(directory / 'sharingd-last-restore.json', restored)
        else:
            write_state(self.cache / 'sharingd-last-restore.json',
                        {'directory': str(directory), 'state': restored})
        self.journal.unlink()
        return restored

    def _recover_under_lock(self):
        record = self.read_journal()
        if record is None:
            return None
        birth = record['controller_birth']
        if process_birth(birth[0]) == tuple(birth):
            raise RuntimeError('The sharingd restoration controller is still running')
        restored = self._restore(record)
        return {'directory': record['directory'], 'original_restored': is_original(restored)}

    @classmethod
    def recover_abandoned(cls):
        agent = cls()
        try:
            agent.acquire()
            return agent._recover_under_lock()
        finally:
            if agent.lock is not None:
                agent.lock.close()

    def start(self, configuration):
        self.acquire()
        try:
            self._recover_under_lock()
            if not is_original(service(self.target)):
                raise RuntimeError('sharingd does not have its original configuration')
            self.directory.chmod(0o700)
            plist = self.directory / 'sharing.plist'
            plist.write_bytes(plistlib.dumps(configuration))
            plist.chmod(0o600)
            birth = process_birth(os.getpid())
            if birth is None:
                raise RuntimeError('Cannot record sharingd controller identity')
            write_state(self.journal, {'schema_version': 1, 'controller_birth': list(birth),
                'directory': str(self.directory), 'plist_sha256': hashlib.sha256(plist.read_bytes()).hexdigest()})
            self.owned = True  # Journal precedes bootout, including observation timeouts.
            reply = launchctl('bootout', self.target)
            if reply.returncode:
                raise RuntimeError('sharingd bootout failed: ' + reply.stderr.strip())
            reply = launchctl('bootstrap', self.domain, str(plist))
            if reply.returncode:
                raise RuntimeError('sharingd bootstrap failed: ' + reply.stderr.strip())
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if not self.owned:
                return None
            record = self.read_journal()
            if (record is None or record['directory'] != str(self.directory)
                    or tuple(record['controller_birth']) != process_birth(os.getpid())):
                raise RuntimeError('sharingd ownership journal changed during the session')
            restored = self._restore(record)
            self.owned = False
            return restored
        finally:
            if self.lock is not None:
                self.lock.close()
                self.lock = None
