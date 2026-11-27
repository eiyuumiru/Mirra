#!/usr/bin/env python3
"""Explicit support-window actions using the existing service controller."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from certificates import CertificateError, current_certificate
from configuration import load_config
from installation import CERTIFICATE_LOCK_REVISION, NativeService
from readiness import bridge_update_report, observe
from activity import capture, FileLog, emit, poll_errors
from preflight import check as check_connection


def renew_certificate(service):
    manifest = service.validate_package()
    if manifest.get('support_revision', 0) < CERTIFICATE_LOCK_REVISION:
        return {'ok': False, 'message': 'Update Mirra support before requesting renewal.', 'report': observe(service)}
    config = load_config(service.package / 'config.json')
    update = bridge_update_report(config)
    if update is not None:
        return {'ok': False, 'message': update['detail'], 'report': update}
    try:
        current_certificate(config, service.package / 'runtime' / 'certificate-renewal.json',
                            lambda: emit('Certificate', 'manual renewal requested'), force=True)
    except CertificateError as error:
        return {'ok': False, 'message': str(error), 'report': observe(service)}
    report = observe(service)
    detail = ('Background support is ready.' if report['state'] == 'ready'
              else 'Mirra will use it the next time background support connects.')
    return {'ok': True, 'message': 'A valid bridge certificate is available. ' + detail, 'report': report}


def control():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'start', 'stop', 'install', 'preflight', 'renew'))
    parser.add_argument('--profile')
    args = parser.parse_args()
    if args.profile and args.action != 'install':
        parser.error('A profile can only be selected for installation')
    service = NativeService()
    emit('Service', 'request', action=args.action)
    try:
        if args.action == 'preflight':
            checked = check_connection(service)
            value = {'ok': True, 'report': checked['report'], 'preflight': checked}
        elif args.action == 'renew':
            value = renew_certificate(service)
        elif args.action == 'install':
            if args.profile:
                if service.registration():
                    raise RuntimeError('Stop support before selecting a different bridge')
                service.prepare(load_config(args.profile), replace_package=service.package.exists())
            elif not service.package.exists():
                raise RuntimeError('Choose a provisioned bridge profile first')
            else:
                service.update_saved()
            if args.profile:
                service.install()
        elif args.action in ('start', 'stop'):
            getattr(service, args.action)()
        if args.action not in ('preflight', 'renew'):
            value = {'ok': True, 'report': observe(service)}
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        # Exception messages can contain private paths/account information.
        # The separate CLI remains available for owner-local detailed diagnosis.
        value = {'ok': False, 'message': 'The action could not finish. Refresh status before trying again. If the problem persists, use the setup guide and keep the existing diagnostics.',
                 'report': observe(service)}
    print(json.dumps(value))
    emit('Service', 'reply', result=value)
    return 0 if value['ok'] else 1


def main():
    log = FileLog(Path.home() / 'Library/Application Support/Mirra/logs', name='control.log')
    if sys.argv[1:2] == ['status']:
        log = poll_errors(log)
    with capture(log):
        return control()


if __name__ == '__main__':
    raise SystemExit(main())
