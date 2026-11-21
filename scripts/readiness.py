"""Read-only, public-safe status for the support window and command line."""
import json
import os
from pathlib import Path
import stat
import subprocess
from datetime import datetime, timezone

from health import health
from configuration import load_config
from processes import NativeAppObserver, process_birth
from launcher import NativeLaunchAgent, AGENT
from installation import NativeService
from activity import emit
from bridgeclient import BRIDGE_REVISION, bridge_revision, has_ssh_access, read_token, request_json


def report(code, title, detail, *, actions=(), transport=None):
    return {'schema_version': 1, 'observed_at': datetime.now(timezone.utc).isoformat(),
            'state': code, 'title': title, 'detail': detail,
            'actions': list(actions), 'bridge_transport': transport,
            'mirroring_connection_verified': None}


def bridge_update_report(config, timeout=2):
    if not config.token_file.is_file():
        return None
    try:
        status, reply = request_json(config, read_token(config.token_file), 'GET', '/v1/status', timeout=timeout)
    except OSError:
        return None
    revision = bridge_revision(reply) if status == 200 else None
    if revision is None or revision >= BRIDGE_REVISION:
        return None
    if has_ssh_access(config):
        detail = 'Update Mirra Bridge on the iPhone through its saved SSH connection.'
        actions = ('update_bridge', 'refresh')
    else:
        detail = 'Update the iPhone from a Mac with verified SSH access to this bridge, then check again here.'
        actions = ('refresh', 'guide')
    return report('bridge_update_available', 'Bridge update available', detail, actions=actions,
                  transport=config.transport)


def read_private(service, path):
    service.private_file(path)
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError('Invalid support state')
    return value


def broker_socket(service, directory):
    record = read_private(service, directory / 'broker-workspace.json')
    path = Path(record['path'])
    if (record.get('schema_version') != 1 or path.parent.resolve() != Path('/tmp').resolve()
            or not path.name.startswith('mirra-')):
        raise ValueError('Unexpected broker workspace')
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or (info.st_dev, info.st_ino) != (record.get('device'), record.get('inode'))):
        raise ValueError('Broker workspace changed')
    endpoint = path / 'broker.sock'
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Unexpected broker socket')
    return endpoint


def mirroring_needs_relaunch(configuration, run, backend, children):
    if type(backend.get('attempt')) is not int or backend['attempt'] < 1:
        raise ValueError('Invalid backend attempt')
    if backend['attempt'] == 1:
        return False
    birth = children['sharingd']
    if (not isinstance(birth, list) or len(birth) != 4 or any(type(value) is not int for value in birth)
            or birth[0] <= 0 or birth[1] != os.getuid() or birth[2] <= 0 or not 0 <= birth[3] < 1000000
            or process_birth(birth[0]) != tuple(birth)):
        raise ValueError('Recovered sharingd changed during observation')
    observer = NativeAppObserver(configuration.system_app / 'Contents/MacOS/iPhone Mirroring',
                                 run / 'sockets.dylib')
    pids = observer.poll()
    if observer.last_errors:
        raise RuntimeError('Mirroring app observation did not finish')
    stale = False
    for pid in pids:
        identity = observer.verified[pid]
        if observer.identity(pid) != identity:
            raise RuntimeError('Mirroring app changed during observation')
        stale = stale or identity[1:] <= tuple(birth[2:])
    if process_birth(birth[0]) != tuple(birth):
        raise ValueError('Recovered sharingd changed during observation')
    return stale


def observe(service=None, *, timeout=2):
    """Never starts/stops a service, repairs a file, or infers video from health.

    The snapshot is rechecked after the live query. Missing observations and
    changing generations remain unknown, so the UI cannot offer stale readiness.
    Only selected fields leave this function; private paths, addresses, tokens,
    identifiers, exception messages and notification contents are not included.
    """
    service = service or NativeService()
    if not service.package.exists():
        return report('setup_required', 'Set up your bridge',
                      'Open Setup to connect to an existing Mirra Bridge or set up a new bridge iPhone.',
                      actions=('setup',))
    try:
        manifest = service.validate_package()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        emit('Status', 'installation validation failed', 'error', error_type=type(error).__name__, error=str(error))
        return report('installation_changed', 'The support installation needs attention',
                      'Some installed files are missing or changed. Keep the existing diagnostics and use the setup guide to repair the package.',
                      actions=('guide', 'refresh'))
    try:
        configuration = load_config(service.package / 'config.json')
        transport = configuration.transport
        if service.needs_update(manifest):
            return report('update_available', 'Update Mirra support',
                          'Choose Update and connect to install this version’s support using your saved bridge setup.',
                          actions=('install', 'guide'), transport=transport)
        update = bridge_update_report(configuration, timeout)
        before = service.status()
        if update is not None and not before.get('backend_ready'):
            if before.get('registered'):
                update['actions'].append('stop')
            return update
        if not before.get('registered'):
            if before.get('supervisor_alive'):
                return report('stopping', 'Finishing shutdown',
                              'Support is still closing its previous session. Wait before starting it again.',
                              actions=('refresh',), transport=transport)
            enabled = before.get('login_enabled')
            return report('stopped', 'Support is stopped',
                          'Start support, then open Apple’s iPhone Mirroring.' if enabled else
                          'Enable support at login to use your saved bridge setup.',
                          actions=('start' if enabled else 'install', 'setup', 'guide'), transport=transport)
        if before.get('startup_failure'):
            code = before['startup_failure']
            title, detail = {
                'container_access_denied': ('Allow access to Mirroring support',
                    'macOS denied access to iPhone Mirroring’s temporary folder. Go back to Settings, stop support, then start it and choose Allow in the macOS prompt.'),
                'container_missing': ('Open iPhone Mirroring once',
                    'Apple’s iPhone Mirroring has not created its temporary folder. Open the app once and quit it, then go back to Settings and stop and start support.'),
                'support_access_denied': ('Support needs file access',
                    'macOS denied a file operation during startup. Check the service log, then go back to Settings and stop and start support when you are ready to retry.'),
                'startup_interrupted': ('Support startup was interrupted',
                    'The previous startup ended unexpectedly. Automatic retries are paused. Check the service log, then go back to Settings and stop and start support.')
            }.get(code, ('Support could not start',
                'Automatic retries are paused after a support failure. Check the service log for the reason, then go back to Settings and stop and start support.'))
            return report('startup_failed', title, detail,
                          actions=('stop', 'refresh', 'guide'), transport=transport)
        if before.get('supervisor_alive') and before.get('phase') == 'waiting_for_mirroring_exit':
            return report('waiting_for_mirroring_exit', 'Quit iPhone Mirroring',
                          'Quit Apple’s iPhone Mirroring with Command-Q. Support will continue automatically; wait until Mirra is ready before opening it again.',
                          actions=('refresh', 'stop'), transport=transport)
        if not before.get('supervisor_alive') or not before.get('native_launch_support_ready'):
            return report('starting', 'Preparing app support',
                          'The background service is starting or restoring its previous session. Check again shortly.',
                          actions=('refresh', 'stop'), transport=transport)
        run = service.package / 'runtime' / before['run']
        backend = read_private(service, run / 'backend-status.json')
        if not before.get('backend_ready'):
            certificate_issue = backend.get('certificate_issue')
            if certificate_issue == 'renewing':
                return report('renewing_certificate', 'Renewing bridge certificate',
                              'Mirra is requesting a current certificate from your bridge.',
                              actions=('refresh', 'stop'), transport=transport)
            if certificate_issue == 'expired':
                return report('bridge_certificate_expired', 'Bridge certificate expired',
                              'Keep the bridge iPhone online. Mirra will retry automatically, or you can request another renewal now.',
                              actions=('renew', 'refresh', 'stop'), transport=transport)
            if certificate_issue in ('clock', 'invalid', 'unavailable'):
                detail = ('Check the date and time on the Mac and bridge iPhone.' if certificate_issue == 'clock'
                          else 'Mirra could not read a valid certificate from the bridge.')
                return report('bridge_certificate_unavailable', 'Couldn’t validate the bridge certificate', detail,
                              actions=('refresh', 'stop', 'guide'), transport=transport)
            if backend.get('phase') in ('failed', 'stopped') or not backend.get('automatic_recovery'):
                return report('needs_attention', 'Background support needs attention',
                              'Automatic reconnection is not running. Check the bridge connection, then stop and start support.',
                              actions=('refresh', 'stop', 'guide'), transport=transport)
            cleanup = backend.get('phase') in ('waiting_for_cleanup', 'restoring', 'stopping_worker')
            return report('restoring' if cleanup else 'waiting_for_bridge',
                          'Restoring the previous connection' if cleanup else 'Waiting for the bridge',
                          'Support is finishing cleanup before reconnecting. Check again shortly.' if cleanup else
                          ('Keep the bridge reachable on Wi-Fi with its jailbreak active. Support will retry automatically.'
                           if transport == 'ssh' else 'Connect the selected bridge by USB and keep its jailbreak active. Support will retry automatically.'),
                          actions=('refresh', 'stop', 'guide'), transport=transport)
        name = backend.get('directory', '')
        if not isinstance(name, str) or not name.startswith('backend-') or Path(name).name != name:
            raise ValueError('Unexpected backend directory')
        directory = run / name
        children = read_private(service, directory / 'backend-children.json')
        birth = children['broker']
        if process_birth(birth[0]) != tuple(birth):
            raise ValueError('Broker changed during observation')
        endpoint = broker_socket(service, directory)
        response = health(endpoint, timeout)
        launch = NativeLaunchAgent(run, {}).state()
        relaunch = (response.get('ready') is True
                    and mirroring_needs_relaunch(configuration, run, backend, children))
        after = service.status()
        current = read_private(service, run / 'backend-status.json')
        if (before != after or backend != current or process_birth(birth[0]) != tuple(birth)
                or not after.get('backend_ready')):
            raise ValueError('Support changed during observation')
        launch_ready = (launch.get('path') == str(run / 'native-launch-agent.plist')
                        and launch.get('program') == AGENT and launch.get('injected') is True
                        and launch.get('pid') and process_birth(int(launch['pid'])) is not None)
        if not launch_ready:
            return report('launch_support_unavailable', 'App launch support is unavailable',
                          'The bridge answered, but normal app startup is not confirmed. Check again; if this persists, stop and start support after closing Mirroring.',
                          actions=('refresh', 'stop', 'guide'), transport=transport)
        if response.get('ready') is False:
            return report('recovering', 'The bridge connection needs recovery',
                          'The bridge reported a failure. Background support is monitoring it and will reconnect after cleanup. Check again shortly.',
                          actions=('refresh', 'stop', 'guide'), transport=transport)
        if response.get('ready') is not True:
            raise ValueError('Unknown broker health')
        if relaunch:
            return report('waiting_for_mirroring_exit', 'Quit iPhone Mirroring',
                          'Support has reconnected. Quit Apple’s iPhone Mirroring with Command-Q to close the previous session, then refresh Mirra and choose Connect to start a fresh one.',
                          actions=('refresh', 'stop'), transport=transport)
        ready = report('ready', 'Bridge is ready',
                       'Choose Connect to find your iPhone in Apple’s iPhone Mirroring. Keep it locked and nearby, with Wi-Fi and Bluetooth on. The bridge is available; the iPhone connection is not yet confirmed.',
                       actions=('open_mirroring', 'refresh', 'stop'), transport=transport)
        if update is not None:
            ready['bridge_update_detail'] = update['detail']
            if 'update_bridge' in update['actions']:
                ready['actions'].append('update_bridge')
        return ready
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        emit('Status', 'observation failed', 'error', error_type=type(error).__name__, error=str(error))
        return report('unknown', 'Couldn’t confirm the current connection',
                      'The check did not finish or support changed while being checked. Refresh in a moment. This check has not restarted support.',
                      actions=('refresh', 'guide'))
