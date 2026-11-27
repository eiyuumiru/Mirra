"""Create independent backend profiles and deploy a separately validated endpoint."""
import argparse
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
import time

from transport import Endpoint, EndpointError
from bridgeclient import BridgeError, TOKEN_ALPHABET, display_token, normalize_token, request, request_json
from configuration import ROOT, load_config
from state import write_state
from macho import require_ios_endpoint
from keystore import bridge_capabilities, verify_attested_key
from bridgepaths import (ENVIRONMENT_SCRIPT, ROOTHIDE_CODE_ROOT, ROOTHIDE_ENTITLEMENTS, ROOTLESS_DEPLOYMENT_ROOT,
                         helper_command)
import activity


class RemoteSetupError(EndpointError):
    pass


def destination(config):
    return ('127.0.0.1', config.listen_port) if config.transport == 'usb' else (config.ssh_host, config.ssh_port)


def fingerprints(data):
    values = []
    for line in data.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'):
            raise ValueError('Unsupported SSH host key record')
        blob = base64.b64decode(fields[2], validate=True)
        value = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        values.append((value, line))
    if not values:
        raise ValueError('No SSH host keys found')
    return values


def exclusive_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Publish complete bytes without replacing an existing file, even if the
    # process exits during writing. A partial profile must never look usable.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.write', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.link(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def new_profile(output, user, *, product='', serial='', transport='usb', host='127.0.0.1', port=None,
                device_port=22):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', user):
        raise ValueError('Supply one SSH account name')
    output = Path(output).expanduser().resolve()
    port = (2222 if transport == 'usb' else 22) if port is None else port
    directory = output.parent
    paths = {'user_file': directory / 'user', 'identity_file': directory / 'identity',
             'known_hosts_file': directory / 'known_hosts', 'certificate_file': directory / 'certificate.der',
             'token_file': directory / 'token'}
    for path in [output, *paths.values(), Path(str(paths['identity_file']) + '.pub')]:
        if path.exists() or path.is_symlink():
            raise FileExistsError('New profile would overwrite ' + str(path))
    base = load_config(ROOT / 'config/example.json')
    configured = replace(base, source=output, product_type=product, serial=serial,
        transport=transport, ssh_host=host, ssh_port=port if transport == 'ssh' else 22,
        listen_port=port if transport == 'usb' else base.listen_port, device_port=device_port, **paths)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Validate all user settings before key creation or device access.
    check = directory / ('.validate-' + secrets.token_hex(8) + '.json')
    try:
        write_state(check, configured.as_dict())
        load_config(check)
    finally:
        check.unlink(missing_ok=True)
    activity.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'Mirra',
                    '-f', str(paths['identity_file'])], check=True, timeout=15)
    paths['identity_file'].chmod(0o600)
    Path(str(paths['identity_file']) + '.pub').chmod(0o600)
    exclusive_write(paths['user_file'], (user + '\n').encode())
    exclusive_write(output, (json.dumps(configured.as_dict(), indent=2) + '\n').encode())
    return {'profile': str(output), 'public_key': str(paths['identity_file']) + '.pub',
            'next': 'Verify and enroll the SSH host fingerprint, then authorize this public key'}


def pin_host(config, expected, key_type='ed25519'):
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', expected):
        raise ValueError('A verified SHA256 SSH host fingerprint is required')
    if config.known_hosts_file.exists() or config.known_hosts_file.is_symlink():
        raise FileExistsError('Host-key enrollment never overwrites an existing pin')
    host, port = destination(config)
    reply = activity.run(['ssh-keyscan', '-T', '5', '-t', key_type, '-p', str(port), host],
                           capture_output=True, timeout=10)
    if reply.returncode:
        raise RuntimeError('Cannot obtain the configured SSH host key')
    matching = [line for fingerprint, line in fingerprints(reply.stdout) if fingerprint == expected]
    if len(set(matching)) != 1:
        raise RuntimeError('The SSH host key does not match the verified fingerprint; no pin saved')
    fields = matching[0].split()
    if config.host_key_alias:
        # HostKeyAlias is the exact known_hosts lookup name, independent of port.
        fields[0] = config.host_key_alias
    exclusive_write(config.known_hosts_file, (' '.join(fields) + '\n').encode())
    return {'host_key_verified': True, 'fingerprint': expected, 'known_hosts': str(config.known_hosts_file)}


def remote(config, arguments, data=None, timeout=20):
    reply = activity.run(config.ssh_command(arguments), source='SSH', input=data,
                         record_stdout=not (arguments and arguments[0] == 'cat'),
                         capture_output=True, timeout=timeout)
    if reply.returncode:
        stderr = reply.stderr.decode(errors='replace').strip()
        # Verbose SSH output belongs in the live log. Its handshake must not
        # displace the remote launch/dyld error at the end of a saved summary.
        meaningful = [line for line in stderr.splitlines() if not re.match(
            r'^(?:debug[123]:|Transferred:|Bytes per second:)', line)
            or re.search(r'\brtype exit-signal\b|\bExit status -1\b', line)]
        message = '\n'.join(meaningful)[-1500:] or stderr[-1500:]
        details = {'ssh_exit_code': reply.returncode}
        for line in stderr.splitlines():
            if line.startswith('MIRRA_HELPER '):
                try:
                    event = json.loads(line[len('MIRRA_HELPER '):])
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get('event') == 'exit' and type(event.get('exit_status')) is int:
                    details.update(helper_stage=event.get('stage'), remote_exit_status=event['exit_status'])
        if re.search(r'\brtype exit-signal\b', stderr):
            details['remote_exit_signal_received'] = True
        code = None
        try:
            error = json.loads(reply.stdout)
            if isinstance(error, dict) and isinstance(error.get('error'), str):
                code = error['error']
                message = message or code
                capabilities = bridge_capabilities(error)
                if capabilities:
                    details['capabilities'] = capabilities
                for name in ('error_code', 'completed'):
                    if type(error.get(name)) is (bool if name == 'completed' else int):
                        details[name] = error[name]
                missing = error.get('missing_symbols')
                if isinstance(missing, list) and missing and all(
                        isinstance(s, str) and re.fullmatch(r'aks_[a-z0-9_]+', s) for s in missing):
                    message += ': ' + ', '.join(missing)
        except (ValueError, UnicodeError):
            pass
        raise RemoteSetupError('Remote setup command failed: ' + (message or str(reply.returncode)), code, details)
    return reply.stdout


def bridge_environment(config):
    value = json.loads(remote(config, ['sh', '-c', ENVIRONMENT_SCRIPT]))
    if not isinstance(value, dict) or value.get('path_mode') not in ('native', 'roothide'):
        raise RemoteSetupError('The bridge returned an invalid filesystem report',
                               'roothide_path_translation_unavailable')
    if value['path_mode'] == 'roothide' and value.get('path_translation_verified') is not True:
        raise RemoteSetupError('RootHide path conversion could not be verified',
                               'roothide_path_translation_unavailable')
    activity.emit('Bridge', 'filesystem inspected', **value)
    return value


def remote_helper(config, arguments, timeout=20):
    try:
        return remote(config, helper_command(arguments, config.path_mode, observed=True), timeout=timeout)
    except RemoteSetupError as error:
        status = error.details.get('remote_exit_status')
        if error.code is None and (error.details.get('remote_exit_signal_received')
                                  or type(status) is int and 128 <= status <= 255):
            error.code = 'helper_terminated'
        raise


def signing_tool(config):
    # Noninteractive SSH shells need not include the jailbreak prefix in PATH.
    # /var/jb is the rootless bootstrap's stable link, including relocated roots.
    script = '''mirra_signer=$(command -v ldid 2>/dev/null)
if test -n "$mirra_signer" && test -x "$mirra_signer"; then
    printf '%s\\n' "$mirra_signer"
    exit 0
fi
for mirra_signer in /var/jb/usr/bin/ldid /usr/bin/ldid; do
    if test -x "$mirra_signer"; then
        printf '%s\\n' "$mirra_signer"
        exit 0
    fi
done
printf '%s\\n' '{"error":"missing_ldid"}'
exit 1
'''
    path = remote(config, ['sh', '-c', script]).decode().strip()
    if not path.startswith('/') or any(ord(c) < 32 for c in path):
        raise RemoteSetupError('The phone returned an invalid signing-tool path', 'missing_ldid')
    return path


def authorize(config, bootstrap=None, interactive=False, askpass=None):
    public = Path(str(config.identity_file) + '.pub').read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+=*(?: [^\r\n]*)?', public):
        raise ValueError('Expected one generated Ed25519 public key')
    if bootstrap is not None:
        if destination(bootstrap) != destination(config) or bootstrap.user_file.read_text().strip() != config.user_file.read_text().strip():
            raise ValueError('Bootstrap access must target the same host, port and account')
        if {v for v, _ in fingerprints(bootstrap.known_hosts_file.read_bytes())} != {v for v, _ in fingerprints(config.known_hosts_file.read_bytes())}:
            raise ValueError('Bootstrap and new profile must trust the same SSH host key')
    elif not interactive:
        raise ValueError('Use --interactive for SSH password entry, or an existing --bootstrap-config')
    script = '''umask 077
mkdir -p "$HOME/.ssh" || exit 1
chmod 700 "$HOME/.ssh" || exit 1
mirra_authorized_keys="$HOME/.ssh/authorized_keys"
test ! -L "$mirra_authorized_keys" || exit 1
touch "$mirra_authorized_keys" || exit 1
chmod 600 "$mirra_authorized_keys" || exit 1
IFS= read -r mirra_public_key || exit 1
if ! grep -Fqx -- "$mirra_public_key" "$mirra_authorized_keys"; then
    printf '%s\\n' "$mirra_public_key" >> "$mirra_authorized_keys" || exit 1
fi
'''
    args = (bootstrap or config).ssh_command(['sh', '-c', script])
    if interactive:
        # OpenSSH gets the password from the terminal or a native askpass UI.
        # The provisioning process never reads or stores it.
        args = [value.replace('BatchMode=yes', 'BatchMode=no') for value in args]
        args[1:1] = ['-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no']
    options = {}
    if askpass is not None:
        if not interactive or not Path(askpass).is_absolute() or not os.access(askpass, os.X_OK):
            raise ValueError('A native password helper is required for graphical SSH authorization')
        options = {'env': {**os.environ, 'SSH_ASKPASS': str(askpass), 'SSH_ASKPASS_REQUIRE': 'force',
                           'DISPLAY': os.environ.get('DISPLAY', 'mirra-setup')}, 'start_new_session': True}
    activity.run(args, source='SSH', input=(public + '\n').encode(), check=True, timeout=120, **options)
    remote(config, ['true'])
    return {'public_key_authorized': True, 'key_login_verified': True}


SERVICE_LABEL = 'com.mirra.bridge'
SERVICE_DIRECTORY = '/var/mobile/Library/Mirra/Service'
SETTINGS_DOMAIN = 'com.mirra.bridge'
SERVICE_PATH = '/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'


def deployment_input(config):
    value = config.as_dict()
    if config.transport == 'usb':
        # Each wizard invocation owns a new temporary forwarder port. Device
        # selector, device SSH port and host pin still identify the same phone.
        value['backend']['usb'].pop('listen_port')
    return value


def verify_key(config, digest, token=None):
    activity.emit('Certificate', 'attested-key verification begin', certificate_sha256=digest)
    with Endpoint(config, expected_certificate_sha256=digest, token=token) as endpoint:
        if endpoint.ready.get('dcrt_sha256') != digest:
            raise RuntimeError('Bridge service is using a different device certificate')
        # A key accepted by the bridge may still have a layout the host broker
        # cannot adapt. Check the actual broker wire format before publishing.
        proof = verify_attested_key(endpoint)
        activity.emit('Certificate', 'attested-key verification complete', wire_layout=proof,
                      generate_status=0, validate_status=0)
        return proof


def service_plist(binary, directory, port, user, *, roothide=False):
    value = {'Label': SERVICE_LABEL, 'ProgramArguments': [binary, '--serve', directory, '--port', str(port)],
             'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10}
    if user != 'root':
        value['UserName'] = user
    if roothide:
        # RootHide rewrites daemon paths into its randomized root unless a plist
        # is marked as already converted. These paths are real ones already.
        value.update({'ExecuteAllowed': True, '__Patched': True})
    return plistlib.dumps(value)


SETTINGS_BUNDLE = 'MirraBridge'
SETTINGS_CONTROLLER = 'MirraBridgeListController'


def settings_bundle_info():
    return plistlib.dumps({'CFBundleExecutable': SETTINGS_BUNDLE, 'CFBundleIdentifier': 'com.mirra.bridge.settings',
                           'CFBundleName': SETTINGS_BUNDLE, 'CFBundlePackageType': 'BNDL',
                           'CFBundleInfoDictionaryVersion': '6.0', 'CFBundleVersion': '1',
                           'CFBundleShortVersionString': '1.0', 'CFBundleSupportedPlatforms': ['iPhoneOS'],
                           'MinimumOSVersion': '15.0', 'NSPrincipalClass': SETTINGS_CONTROLLER})


def settings_bundle_entry():
    """The Settings page with Copy Token and saved-Mac removal (src/phone/settings.m)."""
    return plistlib.dumps({'entry': {'cell': 'PSLinkCell', 'label': 'Mirra Bridge', 'bundle': SETTINGS_BUNDLE,
                                     'detail': SETTINGS_CONTROLLER, 'isController': True}})


def settings_plist():
    """A read-only PreferenceLoader pane, used when no Settings bundle was built."""
    def value(label, key):
        return {'cell': 'PSTitleValueCell', 'label': label, 'defaults': SETTINGS_DOMAIN, 'key': key}
    return plistlib.dumps({
        'entry': {'cell': 'PSLinkCell', 'label': 'Mirra Bridge'},
        'title': 'Mirra Bridge',
        'items': [
            {'cell': 'PSGroupCell', 'label': 'Pairing',
             'footerText': 'Mirra on your Mac uses this token to open an encrypted connection to this phone. '
                           'Setup over SSH saves it automatically; enter it yourself only to pair another Mac.'},
            value('Token', 'token'),
            {'cell': 'PSGroupCell', 'label': 'Service'},
            value('Status', 'status'), value('Wi-Fi address', 'address'), value('Port', 'port')]})


def new_token():
    return display_token(''.join(secrets.choice(TOKEN_ALPHABET) for _ in range(24)))


class RootAccess:
    """Run installation scripts as root on the bridge.

    Installing a LaunchDaemon needs root. A root SSH account runs scripts
    directly; otherwise passwordless sudo is tried first, then sudo with the
    account password. That password is read once per setup from the native
    prompt (or the terminal), kept only in memory, sent on SSH stdin and
    forgotten when setup ends.
    """
    def __init__(self, config, askpass=None):
        self.config = config
        self.askpass = askpass
        self.user = config.user_file.read_text().strip()
        self._password = None
        self._passwordless = None

    def run(self, script, *, timeout=60):
        config = self.config
        if self.user == 'root':
            return remote(config, ['sh', '-c', script], timeout=timeout)
        if self._passwordless is not False:
            try:
                reply = remote(config, ['sudo', '-n', 'sh', '-c', script], timeout=timeout)
                self._passwordless = True
                return reply
            except RemoteSetupError as error:
                detail = str(error).lower()
                if 'not found' in detail and 'sudo' in detail:
                    raise RemoteSetupError('The phone has no sudo; set up with its root SSH account',
                                           'sudo_password_required') from error
                if self._passwordless or 'password' not in detail:
                    raise
                self._passwordless = False
        if self._password is None:
            self._password = self._ask()
        try:
            return remote(config, ['sudo', '-S', '-p', '', 'sh', '-c', script], self._password + b'\n',
                          timeout=timeout)
        except RemoteSetupError as error:
            if 'incorrect password' in str(error).lower() or 'try again' in str(error).lower():
                self._password = None
                raise RemoteSetupError('sudo rejected the phone account password', 'sudo_password_rejected') from error
            raise

    def _ask(self):
        prompt = f'Password for “{self.user}” on the phone (used with sudo to install the bridge service)'
        if self.askpass is not None:
            reply = subprocess.run([str(self.askpass), prompt], capture_output=True, timeout=300)
            if reply.returncode:
                raise RemoteSetupError('Installing the bridge service needs the phone account password',
                                       'sudo_password_required')
            return reply.stdout.rstrip(b'\r\n')
        if os.isatty(0):
            import getpass
            return getpass.getpass(prompt + ': ').encode()
        raise RemoteSetupError('Installing the bridge service needs root; use a root SSH account or sudo',
                               'sudo_password_required')

    def forget(self):
        self._password = None


def install_service(config, binary, staging, root_access, *, rootless, roothide=False, signer=None,
                    settings_binary=None):
    """Install and (re)start the bridge LaunchDaemon; return its pairing token.

    The token lives in a fixed service directory, so reinstalling keeps the
    pairing shown in Settings. Only the LaunchDaemon and Settings entry are
    replaced; earlier helper directories are preserved.

    `binary` is the real path launchd executes. RootHide's SSH shell sees a
    virtual root, so it reaches the real service directory through /rootfs
    and gives launchctl the plist's real path.
    """
    quote = shlex.quote
    user = config.user_file.read_text().strip()
    directory = ('/rootfs' if roothide else '') + SERVICE_DIRECTORY
    token_path = directory + '/token'
    # A new token is used only if the phone has none yet (noclobber = O_EXCL).
    # The candidate travels on stdin so it never appears in a command line or log.
    remote(config, ['sh', '-c', 'umask 077; IFS= read -r mirra_token || exit 1; mkdir -p ' + quote(directory)
                    + ' && chmod 700 ' + quote(directory) + ' && { test -s ' + quote(token_path)
                    + ' || { set -C; printf "%s\\n" "$mirra_token" > ' + quote(token_path) + '; }; }'],
           (new_token() + '\n').encode())
    token = normalize_token(remote(config, ['cat', token_path]).decode())
    remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(staging + '/service.plist')],
           service_plist(binary, SERVICE_DIRECTORY, config.service_port, user, roothide=roothide))
    bundle = staging + '/' + SETTINGS_BUNDLE + '.bundle'
    with_bundle = bool(signer and settings_binary and Path(settings_binary).is_file())
    if with_bundle:
        remote(config, ['sh', '-c', 'umask 077; mkdir -p ' + quote(bundle) + ' && cat > ' + quote(bundle + '/' + SETTINGS_BUNDLE)],
               Path(settings_binary).read_bytes())
        remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(bundle + '/Info.plist')], settings_bundle_info())
        remote(config, [signer, '-S', bundle + '/' + SETTINGS_BUNDLE])
    remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(staging + '/settings.plist')],
           settings_bundle_entry() if with_bundle else settings_plist())
    root = '/var/jb' if rootless and not roothide else ''
    daemon = root + '/Library/LaunchDaemons/' + SERVICE_LABEL + '.plist'
    preferences = root + '/Library/PreferenceLoader/Preferences'
    bundles = root + '/Library/PreferenceBundles'
    install_bundle = f'''    mkdir -p {quote(bundles)}
    rm -rf {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new')}
    cp -R {quote(bundle)} {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new')}
    chown -R root:wheel {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new')}
    chmod 755 {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new')} {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new/' + SETTINGS_BUNDLE)}
    chmod 644 {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new/Info.plist')}
    rm -rf {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle')}
    mv {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle.new')} {quote(bundles + '/' + SETTINGS_BUNDLE + '.bundle')}
''' if with_bundle else ''
    resolve = 'jbroot "$daemon"' if roothide else 'printf %s "$daemon"'
    script = f'''set -e
PATH={SERVICE_PATH}
daemon={quote(daemon)}
loaded=$({resolve})
mkdir -p "$(dirname "$daemon")"
if test -e "$daemon"; then launchctl unload "$loaded" >/dev/null 2>&1 || true; fi
cp {quote(staging + '/service.plist')} "$daemon.new"
chown root:wheel "$daemon.new"
chmod 644 "$daemon.new"
mv -f "$daemon.new" "$daemon"
settings=false
if test -d {quote(preferences)}; then
{install_bundle}    cp {quote(staging + '/settings.plist')} {quote(preferences + '/Mirra.plist')}
    chmod 644 {quote(preferences + '/Mirra.plist')}
    settings=true
fi
launchctl load -w "$loaded" >/dev/null 2>&1 || launchctl bootstrap system "$loaded"
printf '{{"settings_entry":%s}}\\n' "$settings"
'''
    reply = json.loads(root_access.run(script))
    activity.emit('Bridge', 'service installed', daemon=daemon, directory=SERVICE_DIRECTORY,
                  roothide=roothide, settings_entry=reply.get('settings_entry') is True, settings_bundle=with_bundle)
    return token, {'service_directory': SERVICE_DIRECTORY, 'service_daemon': daemon,
                   'settings_entry': reply.get('settings_entry') is True}


def wait_for_service(config, token, seconds=25):
    deadline = time.monotonic() + seconds
    while True:
        try:
            status, report = request_json(config, token, 'GET', '/v1/status', timeout=8)
            if status == 200 and report.get('service') == 'mirra-bridge':
                return report
            raise RemoteSetupError('The bridge service returned an invalid status', 'bridge_service_invalid')
        except BridgeError as error:
            if error.code in ('bridge_token_rejected', 'bridge_tls_unavailable') or time.monotonic() > deadline:
                raise RemoteSetupError(str(error), error.code) from error
            time.sleep(1)


def certificate_from_service(config, token, issue, issue_if_missing, *, replace_expired_sha256=None):
    """Export (or first request) the DCRT on the phone and download it over HTTPS-PSK."""
    def export(issue_now):
        with activity.operation('Certificate', 'issue' if issue_now else 'export'):
            payload = {'issue': issue_now}
            if issue_now and replace_expired_sha256 is not None:
                payload['replace_expired_sha256'] = replace_expired_sha256
            status, reply = request_json(config, token, 'POST', '/v1/certificate', payload, timeout=70)
        if status != 200 or not reply.get('certificate_exported'):
            code = reply.get('error') if isinstance(reply.get('error'), str) else None
            details = {name: reply[name] for name in ('error_code', 'completed')
                       if type(reply.get(name)) is (bool if name == 'completed' else int)}
            raise RemoteSetupError('The bridge could not export its device certificate: ' + (code or str(status)),
                                   code, details)
        return reply
    issued = issue
    try:
        exported = export(issue)
    except RemoteSetupError as error:
        if not issue_if_missing or issue or error.code != 'cached_certificate_unavailable':
            raise
        activity.emit('Certificate', 'cached certificate unavailable', 'warning', error_code=error.code)
        exported = export(True)
        issued = True
    if exported.get('issuance_requested') is False:
        issued = False
    status, _, data = request(config, token, 'GET', '/v1/certificate', timeout=20)
    if status != 200 or not 0 < len(data) <= 1048576 or hashlib.sha256(data).hexdigest() != exported.get('sha256'):
        raise RuntimeError('Downloaded device certificate does not match the export')
    activity.emit('Certificate', 'certificate download verified', bytes=len(data), sha256=exported.get('sha256'))
    activity.run(['openssl', 'x509', '-inform', 'DER', '-noout'], source='Certificate', input=data,
                 capture_output=True, check=True, timeout=10)
    return data, issued


def publish_deployment(config, output, record):
    if record.get('schema_version') != 2 or record.get('input') != deployment_input(config):
        raise ValueError('Interrupted deployment belongs to different bridge settings')
    certificate = output.parent / 'certificate.der'
    token_file = output.parent / 'token'
    data = base64.b64decode(record['certificate'], validate=True)
    if hashlib.sha256(data).hexdigest() != record['sha256'] or not 0 < len(data) <= 1048576:
        raise ValueError('Interrupted certificate record changed')
    token = normalize_token(record['token'])
    report = record['report']
    binary_path = report.get('remote_endpoint')
    directory = report.get('service_directory')
    for path in (binary_path, directory):
        if not isinstance(path, str) or not path.startswith('/') or any(ord(c) < 32 for c in path):
            raise ValueError('Invalid saved bridge path')
    deployed = replace(config, source=output, remote_endpoint=binary_path,
                       remote_certificate=directory + '/certificate.der', certificate_file=certificate,
                       token_file=token_file, path_mode='native')
    verify_key(deployed, record['sha256'], token)
    # The ready profile is the commit marker: publish it after all artifacts.
    # A retry may reuse only identical, private, user-owned files.
    artifacts = [(certificate, data), (token_file, (display_token(token) + '\n').encode()),
                 (output.with_suffix('.provisioning.json'), (json.dumps(report, indent=2) + '\n').encode()),
                 (output, (json.dumps(deployed.as_dict(), indent=2) + '\n').encode())]
    for path, contents in artifacts:
        try:
            exclusive_write(path, contents)
        except FileExistsError:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or path.read_bytes() != contents):
                raise ValueError('Existing deployment file differs; preserved for inspection')
    activity.emit('Certificate', 'profile published', profile=str(output), certificate_bytes=len(data))
    return report


def deploy(config, output, binary=None, remote_root='/var/mobile/Library/Caches/Mirra', issue=False,
           issue_if_missing=False, resume=False, askpass=None):
    """Install the bridge service over SSH, then finish setup over the service itself."""
    output = Path(output).expanduser().resolve()
    journal = output.with_suffix('.deployment.json')
    if resume and (journal.exists() or journal.is_symlink()):
        info = journal.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Expected a private deployment record')
        record = json.loads(journal.read_text())
        if record.get('schema_version') == 2:
            return publish_deployment(config, output, record)
        journal.unlink()  # An SSH-era record cannot describe a service install.
    for path in (output, output.parent / 'certificate.der', output.parent / 'token'):
        if path.exists() or path.is_symlink():
            raise FileExistsError('Deployment output already exists: ' + str(path))
    if not remote_root.startswith('/') or any(ord(c) < 32 for c in remote_root):
        raise ValueError('Remote installation root must be an absolute path without control characters')
    binary = Path(binary or ROOT / 'build/endpoint').resolve()
    require_ios_endpoint(binary)
    environment = bridge_environment(config)
    input_config = config
    # Setup commands run in the SSH shell, whose paths RootHide virtualizes.
    config = replace(config, path_mode=environment['path_mode'])
    roothide = config.path_mode == 'roothide'
    rootless = environment.get('rootless') is True
    # Traditional rootless bootstraps need executable files inside /var/jb.
    # RootHide maps the shell's /var into a data container, where iOS refuses
    # Mach-O files; code lives in its bundle-backed code area instead.
    # Honor a custom deployment root. Never replace a previous helper directory.
    if roothide:
        remote_root = ROOTHIDE_CODE_ROOT
    elif rootless and remote_root == '/var/mobile/Library/Caches/Mirra':
        remote_root = ROOTLESS_DEPLOYMENT_ROOT
    activity.emit('Bridge', 'deployment location selected', path_mode=config.path_mode, rootless=rootless,
                  remote_root=remote_root)
    signer = signing_tool(config)
    remote_directory = remote_root.rstrip('/') + '/' + secrets.token_hex(8)
    remote_binary = remote_directory + '/endpoint'
    remote_entitlements = remote_directory + '/endpoint.plist'
    root_access = RootAccess(config, askpass)
    try:
        return _deploy(config, input_config, output, journal, binary, remote_root, remote_directory, remote_binary,
                       remote_entitlements, signer, environment, root_access, issue, issue_if_missing, resume)
    finally:
        root_access.forget()


def _deploy(config, input_config, output, journal, binary, remote_root, remote_directory, remote_binary,
            remote_entitlements, signer, environment, root_access, issue, issue_if_missing, resume):
    quote = shlex.quote
    roothide = config.path_mode == 'roothide'
    rootless = environment.get('rootless') is True
    if roothide and root_access.user != 'root':
        # RootHide's code area belongs to root. Create this helper's directory
        # as root once, owned by the SSH account; the rest runs as that account.
        root_access.run('umask 022; mkdir -p ' + quote(remote_root) + ' && chmod 755 '
                        + quote(str(Path(remote_root).parent)) + ' ' + quote(remote_root) + ' && mkdir -m 700 '
                        + quote(remote_directory) + ' && chown ' + quote(root_access.user) + ' '
                        + quote(remote_directory))
        remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(remote_binary)], binary.read_bytes())
    else:
        remote(config, ['sh', '-c', 'umask 077; if ! mkdir -p ' + quote(remote_root)
            + '; then printf \'%s\\n\' \'{"error":"roothide_code_directory_unavailable"}\'; exit 1; fi; mkdir '
            + quote(remote_directory) + ' && cat > ' + quote(remote_binary)], binary.read_bytes())
    entitlements = (ROOT / 'config/endpoint.plist').read_bytes()
    if roothide:
        values = plistlib.loads(entitlements)
        values.update({name: True for name in ROOTHIDE_ENTITLEMENTS})
        entitlements = plistlib.dumps(values)
    remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(remote_entitlements)], entitlements)
    remote(config, [signer, '-S' + remote_entitlements, remote_binary])
    # The service user must be able to execute the helper; it stays private.
    remote(config, ['chmod', '700', remote_binary])
    # One SSH launch checks signing and private APIs before anything is installed.
    capabilities = json.loads(remote_helper(config, [remote_binary, '--capabilities']))
    if capabilities.get('required_symbols_available') is not True:
        raise RuntimeError('The backend lacks required keystore operations')
    # launchd runs the service outside RootHide's virtual root: give it the real path.
    service_binary = remote(config, ['jbroot', remote_binary]).decode().strip() if roothide else remote_binary
    if not service_binary.startswith('/') or any(ord(c) < 32 for c in service_binary):
        raise RemoteSetupError('RootHide returned an invalid helper path', 'roothide_path_translation_unavailable')
    token, service = install_service(config, service_binary, remote_directory, root_access, rootless=rootless,
                                     roothide=roothide, signer=signer, settings_binary=binary.parent / 'settings')
    # From here on, SSH is no longer used: setup continues over the service.
    deployed = replace(config, source=output, remote_endpoint=service_binary,
        remote_certificate=service['service_directory'] + '/certificate.der',
        certificate_file=output.parent / 'certificate.der', token_file=output.parent / 'token', path_mode='native')
    wait_for_service(deployed, token)
    data, certificate_issued = certificate_from_service(deployed, token, issue, issue_if_missing)
    digest = hashlib.sha256(data).hexdigest()
    report = {'profile': str(output), 'remote_directory': remote_directory, 'remote_endpoint': service_binary,
        'setup_path_mode': config.path_mode,
        **service, 'service_port': config.service_port, 'capabilities': capabilities, 'certificate_match': True,
        'certificate_bytes': len(data), 'certificate_issued': certificate_issued,
        'endpoint_sha256_before_signing': hashlib.sha256(binary.read_bytes()).hexdigest(),
        # Publishing below verifies a fresh attested key before writing anything.
        'fresh_attested_key_validated': True, 'native_authentication_and_media_verified': False}
    record = {'schema_version': 2, 'input': deployment_input(input_config), 'report': report, 'token': token,
              'certificate': base64.b64encode(data).decode(), 'sha256': digest}
    if resume:
        write_state(journal, record)
    return publish_deployment(input_config, output, record)


def pair(config, output, token):
    """Pair with an already installed bridge service using the token from its Settings entry."""
    output = Path(output).expanduser().resolve()
    token = normalize_token(token)
    for path in (output, output.parent / 'certificate.der', output.parent / 'token'):
        if path.exists() or path.is_symlink():
            raise FileExistsError('Pairing output already exists: ' + str(path))
    configured = replace(config, source=output, certificate_file=output.parent / 'certificate.der',
                         token_file=output.parent / 'token')
    report = wait_for_service(configured, token, seconds=5)
    if report.get('certificate_available') is not True:
        raise RemoteSetupError('The bridge service has no device certificate yet; finish setup over SSH first',
                               'device_certificate_unavailable')
    status, _, data = request(configured, token, 'GET', '/v1/certificate', timeout=20)
    if status != 200 or not 0 < len(data) <= 1048576 or hashlib.sha256(data).hexdigest() != report.get('dcrt_sha256'):
        raise RuntimeError('Downloaded device certificate does not match the bridge')
    record = {'schema_version': 2, 'input': deployment_input(config), 'token': token,
              'certificate': base64.b64encode(data).decode(), 'sha256': report['dcrt_sha256'],
              'report': {'profile': str(output), 'remote_endpoint': config.remote_endpoint,
                         'service_directory': SERVICE_DIRECTORY, 'service_port': config.service_port,
                         'capabilities': bridge_capabilities(report), 'certificate_match': True,
                         'certificate_bytes': len(data), 'paired_with_token': True,
                         'native_authentication_and_media_verified': False}}
    return publish_deployment(config, output, record)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'pin-host', 'authorize', 'deploy', 'pair'])
    parser.add_argument('--config')
    parser.add_argument('--output')
    parser.add_argument('--user', default='mobile')
    parser.add_argument('--product', default='')
    parser.add_argument('--serial', default='')
    parser.add_argument('--transport', choices=['usb', 'ssh'], default='usb')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int)
    parser.add_argument('--device-port', type=int, default=22, help='SSH port on a USB bridge (default: 22)')
    parser.add_argument('--fingerprint')
    parser.add_argument('--host-key-type', choices=['ed25519', 'ecdsa', 'rsa'], default='ed25519')
    parser.add_argument('--bootstrap-config')
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--binary')
    parser.add_argument('--remote-root', default='/var/mobile/Library/Caches/Mirra')
    parser.add_argument('--issue-certificate', action='store_true')
    parser.add_argument('--token', help='Pairing token shown in the phone’s Settings → Mirra Bridge (pair only)')
    args = parser.parse_args()
    try:
        if args.action == 'init':
            if not args.output:
                parser.error('init requires a new --output profile path')
            result = new_profile(args.output, args.user, product=args.product, serial=args.serial,
                transport=args.transport, host=args.host, port=args.port, device_port=args.device_port)
        else:
            config = load_config(args.config)
            if args.action == 'pin-host':
                result = pin_host(config, args.fingerprint or '', args.host_key_type)
            elif args.action == 'authorize':
                result = authorize(config, load_config(args.bootstrap_config) if args.bootstrap_config else None, args.interactive)
            elif args.action == 'pair':
                if not args.output or not args.token:
                    parser.error('pair requires a new --output profile path and --token')
                result = pair(config, args.output, args.token)
            else:
                if not args.output:
                    parser.error('deploy requires a new --output profile path')
                result = deploy(config, args.output, args.binary, args.remote_root, args.issue_certificate)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
