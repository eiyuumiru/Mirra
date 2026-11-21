"""Exclusive, journaled ownership of the temporary sharingd adapter.

Apple's sharingd job is never replaced. Mirra sets two variables in launchd's
user environment, restarts the job with `kickstart -k` and removes the
variables again, so the adapter loads into the new process while launchd keeps
every sharingd service name registered. Clients (rapportd, Universal Control,
Handoff, AirDrop UI ...) then reconnect by themselves. Replacing the job left a
moment without those names, and clients that tried to reconnect then lost
sharingd until they restarted. Restoring is another `kickstart -k`.

When Mirra stops normally it detaches instead: sharingd keeps running with the
adapter (passing everything else through to Apple's code) and the next start
adopts it. Every new sharingd process makes the iPhone renew the pairing
secret, after which it asks for its passcode once; detaching avoids that on
each stop/start. Updates, removal and new setups restore Apple's sharingd.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import time

from processes import process_birth
from state import write_state

ORIGINAL_PLIST = Path('/System/Library/LaunchAgents/com.apple.sharingd.plist')
PROGRAM = '/usr/libexec/sharingd'
ADAPTER_VARIABLES = ('DYLD_INSERT_LIBRARIES', 'MIRRA_KEYSTORE_CONFIG')
AUTO_UNLOCK = Path.home() / 'Library/Sharing/AutoUnlock'
RESTART_SECONDS = 8


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


def launchd_variables():
    """Adapter variables currently present in launchd's user environment."""
    present = {}
    for name in ADAPTER_VARIABLES:
        reply = launchctl('getenv', name)
        if reply.returncode == 0 and reply.stdout.strip():
            present[name] = reply.stdout.strip()
    return present


def clear_launchd_variables():
    for name in ADAPTER_VARIABLES:
        launchctl('unsetenv', name)
    if launchd_variables():
        raise RuntimeError('Cannot remove the sharingd adapter variables from launchd')


def wait_for_new_process(target, previous, seconds=RESTART_SECONDS):
    deadline = time.monotonic() + seconds
    while True:
        current = service(target)
        if current.get('pid') and current.get('pid') != previous:
            return current
        if time.monotonic() > deadline:
            return current
        time.sleep(0.1)


def _read_plist(path):
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None, plistlib.FMT_BINARY
    fmt = plistlib.FMT_BINARY if data.startswith(b'bplist') else plistlib.FMT_XML
    value = plistlib.loads(data)
    return (value if isinstance(value, dict) else None), fmt


def _write_plist(path, value, fmt, mode):
    temporary = path.with_name('.' + path.name + '.mirra')
    temporary.write_bytes(plistlib.dumps(value, fmt=fmt))
    temporary.chmod(mode)
    os.replace(temporary, path)


def backup_pairing(backup):
    """Copy this Mac's iPhone Mirroring pairing entries out of sharingd's files.

    sharingd keeps the iPhone's signed LTK (ltk.plist, "Remote LTKs") and its
    pairing ID (pairing-records.plist) in plain files. Apple's unmodified
    sharingd, which runs while Mirra is stopped, removes these entries because
    the matching local key validates only through the bridge. Only entries with
    "Attested LTK Data" are copied; entries are added or updated, never removed.
    """
    ltks, _ = _read_plist(AUTO_UNLOCK / 'ltk.plist')
    records, _ = _read_plist(AUTO_UNLOCK / 'pairing-records.plist')
    remote = (ltks or {}).get('Remote LTKs')
    if not isinstance(remote, dict):
        return 0
    saved, _ = _read_plist(backup)
    saved = saved if isinstance(saved, dict) else {}
    changed = False
    for device, entry in remote.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('Attested LTK Data'), bytes):
            continue
        record = (records or {}).get(device)
        value = {'ltk': entry, **({'pairing': record} if isinstance(record, dict) else {})}
        if saved.get(device) != value:
            saved[device] = value
            changed = True
    if changed:
        backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_plist(backup, saved, plistlib.FMT_BINARY, 0o600)
    return len(saved)


def restore_pairing(backup):
    """Put back missing pairing entries before sharingd (with the adapter) loads them."""
    saved, _ = _read_plist(backup)
    if not saved:
        return 0
    ltk_path, record_path = AUTO_UNLOCK / 'ltk.plist', AUTO_UNLOCK / 'pairing-records.plist'
    ltks, ltk_format = _read_plist(ltk_path)
    records, record_format = _read_plist(record_path)
    ltks = ltks if isinstance(ltks, dict) else {}
    records = records if isinstance(records, dict) else {}
    remote = ltks.setdefault('Remote LTKs', {})
    if not isinstance(remote, dict):
        return 0
    restored = 0
    for device, value in saved.items():
        if not isinstance(value, dict) or not isinstance(value.get('ltk'), dict):
            continue
        current = remote.get(device)
        if not isinstance(current, dict) or not isinstance(current.get('Attested LTK Data'), bytes):
            remote[device] = {**(current if isinstance(current, dict) else {}), **value['ltk']}
            restored += 1
        if isinstance(value.get('pairing'), dict) and device not in records:
            records[device] = value['pairing']
            restored += 1
    if restored:
        AUTO_UNLOCK.mkdir(parents=True, exist_ok=True)
        _write_plist(ltk_path, ltks, ltk_format, 0o644)
        _write_plist(record_path, records, record_format, 0o644)
    return restored


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
        self.record = None
        self.restored_pairing = 0
        self.adopted = False

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
        if not isinstance(record, dict) or record.get('schema_version') not in (1, 2):
            raise RuntimeError('Invalid sharingd ownership journal')
        birth = record.get('controller_birth')
        if record.get('detached') is True and birth is None:
            pass  # No controller: the adapter stays loaded between sessions.
        elif (not isinstance(birth, list) or len(birth) != 4 or any(type(n) is not int for n in birth)
                or birth[0] <= 0 or birth[1] != os.getuid()):
            raise RuntimeError('Invalid sharingd controller identity')
        if not isinstance(record.get('directory'), str):
            raise RuntimeError('Invalid sharingd ownership directory')
        directory = Path(record['directory'])
        if not directory.is_absolute() or directory.resolve() != directory:
            raise RuntimeError('Invalid sharingd ownership directory')
        _private_directory(directory)
        digest = 'plist_sha256' if record['schema_version'] == 1 else 'config_sha256'
        if (not isinstance(record.get(digest), str)
                or re.fullmatch('[0-9a-f]{64}', record[digest]) is None):
            raise RuntimeError('Invalid sharingd launch configuration digest')
        if record['schema_version'] == 2 and record.get('injected_pid') is not None \
                and not re.fullmatch('[0-9]{1,10}', str(record['injected_pid'])):
            raise RuntimeError('Invalid sharingd adapter process')
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
        if record['schema_version'] == 2:
            return self._restore_environment(record)
        return self._restore_replaced_job(record)

    def _restore_environment(self, record):
        directory = Path(record['directory'])
        clear_launchd_variables()
        current = service(self.target)
        if not current:
            reply = launchctl('bootstrap', self.domain, str(ORIGINAL_PLIST))
            if reply.returncode:
                raise RuntimeError('Cannot restore original sharingd: ' + reply.stderr.strip())
        elif current.get('program') != PROGRAM or current.get('path') != str(ORIGINAL_PLIST):
            raise RuntimeError('sharingd ownership changed; refusing to replace another configuration')
        else:
            injected = record.get('injected_pid')
            pid = current.get('pid')
            # Without a recorded adapter process, restart anyway: it is harmless.
            if pid and (injected is None or str(pid) == str(injected)):
                reply = launchctl('kickstart', '-k', self.target)
                if reply.returncode:
                    raise RuntimeError('Cannot restart original sharingd: ' + reply.stderr.strip())
                wait_for_new_process(self.target, pid)
        restored = service(self.target)
        if not is_original(restored) or (record.get('injected_pid') is not None
                                         and str(restored.get('pid')) == str(record['injected_pid'])):
            raise RuntimeError('Original sharingd restoration is not verified')
        config = directory / 'keystore.json'
        if _private_directory(directory):
            config.unlink(missing_ok=True)  # Holds the broker credentials.
            write_state(directory / 'sharingd-last-restore.json', restored)
        else:
            write_state(self.cache / 'sharingd-last-restore.json',
                        {'directory': str(directory), 'state': restored})
        self.journal.unlink()
        return restored

    def _restore_replaced_job(self, record):
        """Undo a session started by an earlier Mirra version, which replaced the job."""
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

    def detached_alive(self, record):
        """A detached adapter process that is still the job's running sharingd."""
        if not record or record.get('schema_version') != 2 or record.get('detached') is not True:
            return False
        current = service(self.target)
        return (record.get('injected_pid') is not None and current.get('program') == PROGRAM
                and current.get('path') == str(ORIGINAL_PLIST) and str(current.get('pid')) == str(record['injected_pid']))

    def _recover_under_lock(self, restore_detached=True):
        record = self.read_journal()
        if record is None:
            return None
        if record.get('detached') is True:
            if not restore_detached and self.detached_alive(record):
                return None
        else:
            birth = record['controller_birth']
            if process_birth(birth[0]) == tuple(birth):
                raise RuntimeError('The sharingd restoration controller is still running')
        restored = self._restore(record)
        return {'directory': record['directory'], 'original_restored': is_original(restored)}

    @classmethod
    def recover_abandoned(cls, restore_detached=False):
        """Restore after a lost controller. A detached adapter stays unless asked."""
        agent = cls()
        try:
            agent.acquire()
            return agent._recover_under_lock(restore_detached=restore_detached)
        finally:
            if agent.lock is not None:
                agent.lock.close()

    @classmethod
    def detached_matches(cls, adapter_sha256):
        """True while a detached adapter with exactly this digest is still sharingd.

        A support update that ships the same adapter can then leave sharingd
        running, so the next start adopts it and the iPhone keeps its pairing
        armed instead of asking for its passcode again."""
        agent = cls()
        try:
            agent.acquire()
            record = agent.read_journal()
            return bool(agent.detached_alive(record) and record.get('adapter_sha256') == adapter_sha256)
        finally:
            if agent.lock is not None:
                agent.lock.close()

    @classmethod
    def restore_detached(cls):
        """Give sharingd back to Apple (updates, removal and new setups)."""
        return cls.recover_abandoned(restore_detached=True)

    def start(self, adapter, settings, pairing_backup=None, *, reuse_detached=True):
        """Load `adapter` into Apple's sharingd; `settings` stay in a private file."""
        self.acquire()
        try:
            adapter_digest = hashlib.sha256(Path(adapter).read_bytes()).hexdigest()
            record = self.read_journal()
            if (reuse_detached and self.detached_alive(record)
                    and record.get('adapter_sha256') == adapter_digest):
                birth = process_birth(os.getpid())
                if birth is None:
                    raise RuntimeError('Cannot record sharingd controller identity')
                record.update(controller_birth=list(birth), detached=False, directory=str(self.directory))
                write_state(self.journal, record)
                self.record = record
                self.owned = True
                self.adopted = True
                return
            self._recover_under_lock(restore_detached=True)
            current = service(self.target)
            if not is_original(current):
                raise RuntimeError('sharingd does not have its original configuration')
            if launchd_variables():
                raise RuntimeError('launchd already carries sharingd adapter variables')
            self.directory.chmod(0o700)
            config = self.directory / 'keystore.json'
            config.unlink(missing_ok=True)
            descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                json.dump(settings, output)
            birth = process_birth(os.getpid())
            if birth is None:
                raise RuntimeError('Cannot record sharingd controller identity')
            self.record = {'schema_version': 2, 'controller_birth': list(birth), 'directory': str(self.directory),
                           'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
                           'previous_pid': current.get('pid'), 'injected_pid': None,
                           'adapter_sha256': adapter_digest}
            write_state(self.journal, self.record)
            self.owned = True  # The journal precedes any change to launchd.
            if pairing_backup is not None:
                # Read by the restarted sharingd while it starts.
                self.restored_pairing = restore_pairing(pairing_backup)
            try:
                for name, value in (('DYLD_INSERT_LIBRARIES', str(Path(adapter).resolve())),
                                    ('MIRRA_KEYSTORE_CONFIG', str(config))):
                    reply = launchctl('setenv', name, value)
                    if reply.returncode:
                        raise RuntimeError('Cannot prepare the sharingd adapter: ' + reply.stderr.strip())
                reply = launchctl('kickstart', '-k', self.target)
                if reply.returncode:
                    raise RuntimeError('sharingd restart failed: ' + reply.stderr.strip())
                # launchd copies the environment when it spawns the new process.
                wait_for_new_process(self.target, current.get('pid'))
            finally:
                clear_launchd_variables()
        except BaseException:
            self.close()
            raise

    def record_injected(self, pid):
        """Remember the adapter process, so restoration restarts exactly that one."""
        self.record['injected_pid'] = int(pid)
        write_state(self.journal, self.record)

    def close(self, detach=False):
        try:
            if not self.owned:
                return None
            record = self.read_journal()
            if (record is None or record['directory'] != str(self.directory)
                    or record.get('controller_birth') is None
                    or tuple(record['controller_birth']) != process_birth(os.getpid())):
                raise RuntimeError('sharingd ownership journal changed during the session')
            if detach and record.get('schema_version') == 2 and record.get('injected_pid') is not None:
                record.update(detached=True, controller_birth=None)
                write_state(self.journal, record)
                self.owned = False
                return service(self.target)
            restored = self._restore(record)
            self.owned = False
            return restored
        finally:
            if self.lock is not None:
                self.lock.close()
                self.lock = None
