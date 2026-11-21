"""Replace the enrolled iPhone's bridge executable over its verified SSH connection."""
from contextlib import suppress
from dataclasses import replace
from pathlib import PurePosixPath
import json
import plistlib
import secrets
from shlex import quote
import subprocess
import time

from bridgeclient import (BRIDGE_REVISION, BridgeError, bridge_revision, has_ssh_access,
                          normalize_token, request_json)
from bridgepaths import ROOTHIDE_CODE_ROOT, ROOTHIDE_ENTITLEMENTS
from macho import require_ios_endpoint
from provisioning import (RootAccess, RemoteSetupError, SERVICE_DIRECTORY, SERVICE_LABEL, SERVICE_PATH,
                          bridge_environment, remote, remote_helper, signing_tool, wait_for_service)


def jbroot_path(config, path):
    resolved = remote(config, ['jbroot', str(path)]).decode().strip()
    if (not resolved.startswith('/') or '..' in PurePosixPath(resolved).parts
            or any(ord(character) < 32 for character in resolved)):
        raise RemoteSetupError('RootHide returned an invalid service path', 'bridge_update_unverified')
    return resolved


def confirm_revision(config, token, seconds=30):
    deadline = time.monotonic() + seconds
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            status, reply = request_json(config, token, 'GET', '/v1/status', timeout=min(3, remaining))
        except BridgeError as error:
            if error.code in ('bridge_token_rejected', 'bridge_tls_unavailable'):
                raise
        else:
            if status == 200 and bridge_revision(reply) == BRIDGE_REVISION:
                return
        time.sleep(min(1, remaining))
    raise RemoteSetupError('New bridge did not report its revision', 'bridge_update_unverified')


def update_bridge(config, token, source, askpass):
    current = bridge_revision(wait_for_service(config, token))
    if current is None:
        raise RemoteSetupError('Unrecognized bridge revision', 'bridge_update_unverified')
    if current >= BRIDGE_REVISION:
        return False
    if not has_ssh_access(config):
        raise RemoteSetupError('No saved SSH access for this bridge', 'bridge_update_access_missing')
    environment = bridge_environment(config)
    roothide = environment['path_mode'] == 'roothide'
    root = '/var/jb' if not roothide and environment.get('rootless') is True else ''
    daemon = root + '/Library/LaunchDaemons/' + SERVICE_LABEL + '.plist'
    access = RootAccess(config, askpass)
    definition = plistlib.loads(remote(config, ['cat', daemon]))
    target = PurePosixPath(config.remote_endpoint)
    if (not target.is_absolute() or '..' in target.parts or target.name != 'endpoint'
            or definition.get('Label') != SERVICE_LABEL
            or definition.get('UserName', 'root') != access.user
            or definition.get('ProgramArguments') != [str(target), '--serve', SERVICE_DIRECTORY,
                                                       '--port', str(config.service_port)]):
        raise RemoteSetupError('SSH service differs from the enrolled bridge', 'bridge_update_unverified')
    loaded_daemon = daemon
    service_directory = SERVICE_DIRECTORY
    signing_entitlements = (source / 'config/endpoint.plist').read_bytes()
    if roothide:
        real_code_root = jbroot_path(config, ROOTHIDE_CODE_ROOT)
        if definition.get('__Patched') is not True or not target.is_relative_to(real_code_root):
            raise RemoteSetupError('Bridge does not belong to the current RootHide installation',
                                   'bridge_update_unverified')
        # launchd stores a physical executable path. SSH file operations and
        # ldid take paths relative to the bootstrap's virtual root.
        target = PurePosixPath(ROOTHIDE_CODE_ROOT) / target.relative_to(real_code_root)
        loaded_daemon = jbroot_path(config, daemon)
        service_directory = '/rootfs' + SERVICE_DIRECTORY
        values = plistlib.loads(signing_entitlements)
        values.update({name: True for name in ROOTHIDE_ENTITLEMENTS})
        signing_entitlements = plistlib.dumps(values)
        config = replace(config, path_mode='roothide')
    saved = remote(config, ['cat', service_directory + '/token'])
    if normalize_token(saved.decode()) != token:
        raise RemoteSetupError('SSH pairing differs from the enrolled bridge', 'bridge_update_unverified')

    binary = source / 'build/endpoint'
    require_ios_endpoint(binary)
    signer = signing_tool(config)
    stage = target.parent / ('.mirra-update-' + secrets.token_hex(8))
    candidate, entitlements, backup = (stage / name for name in ('endpoint', 'endpoint.plist', 'previous'))
    remote(config, ['mkdir', '-m', '700', str(stage)])
    restart = f'''export PATH={SERVICE_PATH}
restart() {{
    launchctl kickstart -k system/{SERVICE_LABEL} >/dev/null 2>&1 && return 0
    launchctl unload {quote(loaded_daemon)} >/dev/null 2>&1 || true
    launchctl load -w {quote(loaded_daemon)} >/dev/null 2>&1 || launchctl bootstrap system {quote(loaded_daemon)}
}}'''
    remove_stage = True
    try:
        for path, data in ((candidate, binary.read_bytes()), (entitlements, signing_entitlements)):
            remote(config, ['sh', '-c', 'umask 077; cat > ' + quote(str(path))], data)
        remote(config, [signer, '-S' + str(entitlements), str(candidate)])
        remote(config, ['chmod', '700', str(candidate)])
        capabilities = json.loads(remote_helper(config, [str(candidate), '--capabilities']))
        if (capabilities.get('bridge_revision') != BRIDGE_REVISION
                or capabilities.get('required_symbols_available') is not True):
            raise RemoteSetupError('The staged bridge failed its compatibility check', 'bridge_update_unverified')
        try:
            access.run(f'''set -e
{restart}
test -f {quote(str(target))}
test ! -L {quote(str(target))}
cp -p {quote(str(target))} {quote(str(backup))}
mv -f {quote(str(candidate))} {quote(str(target))}
restart
''')
            confirm_revision(config, token)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            remove_stage = False
            access.run(f'''set -e
{restart}
if test -f {quote(str(backup))}; then
    mv -f {quote(str(backup))} {quote(str(target))}
    restart
fi
''')
            remove_stage = True
            raise
        return True
    finally:
        access.forget()
        if remove_stage:
            with suppress(OSError, RuntimeError, subprocess.SubprocessError):
                remote(config, ['rm', '-rf', str(stage)])
