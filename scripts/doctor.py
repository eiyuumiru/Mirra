#!/usr/bin/env python3
"""Inspect host prerequisites and optionally test a fresh backend signing key."""
import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
from configuration import ConfigError,load_config,ROOT
from usbmux import list_devices,product_type,select_device
from compatibility import inspect_media_profile, supported_apple_app
from hardware import inspect_host_environment
from keystore import bridge_capabilities, verify_attested_key
from transport import EndpointError


def inspect_host(config):
    checks = []
    def add(name,ok,detail):
        checks.append({'check':name,'status':'pass' if ok else 'missing','detail':detail})
    add('architecture',sys.platform=='darwin' and platform.machine()=='x86_64',
        'The current host shim targets Intel macOS; other architectures are unverified')
    try:
        info = plistlib.loads((config.system_app/'Contents/Info.plist').read_bytes())
        version = (info.get('CFBundleShortVersionString'),info.get('CFBundleVersion'))
        add('app_build',supported_apple_app(info),f'Installed {version[0]} ({version[1]}); requires Apple’s 1.x system app and matching framework interfaces')
    except (OSError,ValueError,plistlib.InvalidFileException):
        add('app_build',False,'System iPhone Mirroring app is unavailable')
    for name,path in [('bridge_pairing_token',config.token_file),('device_certificate',config.certificate_file)]:
        try:
            add(name,path.is_file() and path.stat().st_size>0,'Configured provisioning file is present' if path.is_file() else 'Set up or pair the bridge')
        except OSError:
            add(name,False,'Configured provisioning file cannot be read')
    # SSH is only needed to (re)install the bridge service, not to run it.
    for name,path in [('ssh_account',config.user_file),('ssh_key',config.identity_file),
                      ('ssh_host_key',config.known_hosts_file)]:
        try:
            present = path.is_file() and path.stat().st_size>0
        except OSError:
            present = False
        checks.append({'check':name,'status':'pass' if present else 'optional',
                       'detail':'SSH setup access is present' if present else 'Only needed to reinstall the bridge service'})
    for name in ['keystore.dylib','media.dylib',
                 'sockets.dylib','launch.dylib']:
        add(name,(ROOT/'build'/name).is_file(),
            'Built support component; each new session stages its own copy')
    if sys.platform=='darwin':
        try:
            profile = inspect_media_profile()
            checks.append({'check':'media_profile','status':'pass' if profile['compatible'] else 'missing',
                'detail':'Host build and required framework ABI for the accepted AWDL/single-tile profile',
                'report':profile})
        except (OSError,RuntimeError,subprocess.SubprocessError) as error:
            add('media_profile',False,str(error))
        try:
            reply = subprocess.run(['/sbin/ifconfig','awdl0'],capture_output=True,text=True,timeout=5)
            add('awdl',reply.returncode==0 and 'inet6 ' in reply.stdout,'AWDL interface with IPv6; media reliability still requires a live test')
            signature = subprocess.run(['codesign','--verify','--strict',str(config.system_app)],capture_output=True,timeout=10)
            add('system_app_signature',signature.returncode==0,'Original app signature check')
        except (OSError,subprocess.TimeoutExpired):
            add('host_tools',False,'A host inspection command failed or timed out')
    return checks


def inspect_backend(config):
    from transport import Endpoint
    if not config.certificate_file.is_file() or not config.certificate_file.stat().st_size:
        return {'check':'backend_attested_key','status':'missing','detail':'Local device certificate is missing'}
    try:
        with Endpoint(config) as endpoint:
            if not endpoint.ready.get('dcrt_bytes'):
                raise RuntimeError('The bridge service has no certificate')
            wire = verify_attested_key(endpoint)
            certificate_match = endpoint.certificate_binding_verified
            # Public capabilities only: no host, serial, certificate or key.
            capabilities = bridge_capabilities(endpoint.ready)
        return {'check':'backend_attested_key','status':'pass',
                'certificate_binding_verified':certificate_match,
                'wire_layout_validated':wire['original_fields_byte_identical'], 'capabilities':capabilities,
                'detail':'Fresh isolated attested key and broker wire layout validated; native phone authentication is not tested'}
    except EndpointError as error:
        return {'check':'backend_attested_key','status':'missing','detail':str(error),
                'error_code':error.code, 'operation_details':error.details}
    except (OSError,RuntimeError,ValueError) as error:
        return {'check':'backend_attested_key','status':'missing','detail':str(error)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    parser.add_argument('--json',action='store_true')
    parser.add_argument('--devices',action='store_true',help='List USB devices without changing them')
    parser.add_argument('--show-identifiers',action='store_true',help='Include USB serials for local configuration; omit from public reports')
    parser.add_argument('--backend',action='store_true',help='Open a bridge service session and create/validate one disposable signing key')
    parser.add_argument('--hardware',action='store_true',help='Read optional graphics, Wi-Fi/controller bindings, Bluetooth, loaded drivers, AWDL/llw and SIP observations; does not change readiness')
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except ConfigError as error:
        parser.error(str(error))
    if args.devices:
        rows = []
        try:
            for device in list_devices():
                try:
                    product = product_type(device['DeviceID']) or 'unknown'
                except (OSError,ValueError):
                    product = 'unavailable'
                row = {'product_type':product,'transport':'USB'}
                if args.show_identifiers:
                    row['serial'] = device.get('Properties',{}).get('SerialNumber')
                rows.append(row)
        except (OSError,ValueError) as error:
            parser.error(str(error))
        print(json.dumps({'devices':rows},indent=2))
        return 0
    checks = inspect_host(config)
    if config.transport=='usb':
        try:
            select_device(list_devices(),product=config.product_type,serial=config.serial)
            checks.append({'check':'backend_usb','status':'pass','detail':'One configured backend selected'})
        except (OSError,ValueError) as error:
            checks.append({'check':'backend_usb','status':'missing','detail':str(error)})
    if args.backend:
        checks.append(inspect_backend(config))
    report = {'checks':checks,'native_mirroring_verified':False,'daily_use_verified':False,
              'backend_transport':config.transport,'backend_runtime_tested':args.backend}
    if args.hardware:
        report['host_environment'] = inspect_host_environment()
    if args.json:
        print(json.dumps(report,indent=2))
    else:
        for check in checks:
            print(f'{check["status"].upper():7} {check["check"]}: {check["detail"]}')
        if args.hardware:
            for name in ('host', 'graphics', 'wifi', 'network_controllers', 'pci_inventory', 'bluetooth', 'loaded_drivers', 'awdl', 'llw', 'sip'):
                observation = report['host_environment'][name]
                print(f'{observation["status"].upper():8} {name}: '
                      + json.dumps(observation, separators=(',', ':')))
        print('These checks do not verify a complete Mirroring session or daily-use stability.')
    return 0 if all(c['status'] in ('pass','optional') for c in checks) else 1


if __name__=='__main__':
    raise SystemExit(main())
