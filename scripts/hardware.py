"""Optional, read-only host observations; never used to gate a connection."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
from xml.parsers.expat import ExpatError

from configuration import ROOT
from redaction import redact_text

CONTROLLER_FIELDS = {
    'chipset': 'chipset', 'firmwareversion': 'firmware_version',
    'vendorid': 'vendor_id', 'productid': 'product_id',
    'transport': 'transport', 'state': 'state',
    'supportedservices': 'supported_services', 'lmpversion': 'lmp_version',
    'lowenergysupported': 'low_energy_supported',
    'bluetoothlowenergysupported': 'low_energy_supported',
    'handoffsupported': 'handoff_supported', 'manufacturer': 'manufacturer',
}
DRIVERS = re.compile(
    r'BlueToolFixup|Brcm|Airport|itlwm|IntelBluetooth|IntelBTPatcher|'
    r'IOBluetooth|IO80211|AppleBluetooth|BT4LEContinuity|MtkWireless|'
    r'Lilu|WhateverGreen|NootedRed|NootRX|AMDRadeon|AMD.*(?:Controller|Framebuffer)|'
    r'AppleIntel.*(?:Graphics|Framebuffer)|IOGraphics|IOAccelerator|'
    r'NVDA|NVIDIA|GeForce|NVMTL|NullMoth', re.I)
DECODE_STATUSES = ('format_status', 'session_status', 'hardware_query_status',
                   'block_status', 'copy_status', 'sample_status',
                   'submit_status', 'wait_status', 'output_status')


def unknown(reason):
    return {'status': 'unknown', 'reason': reason}


def safe_hardware_text(value):
    # Only use this for selected hardware fields, never whole command output.
    value = redact_text(value).replace(str(Path.home()), '<home>')
    value = re.sub(r'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}', '<address>', value)
    value = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '<account>', value)
    return value.replace('\n', ' ').replace('\t', ' ')[:256]


def command(arguments, timeout):
    """Discard stderr and command error text, which may contain personal data."""
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, unknown('timeout')
    except OSError:
        return None, unknown('tool_unavailable')
    if result.returncode:
        return None, {**unknown('command_failed'), 'exit_code': result.returncode}
    # Parse locally without retaining raw profiler inventories or driver UUIDs.
    if len(result.stdout) > 4 * 1024 * 1024:
        return None, unknown('output_limit')
    return result.stdout, {'status': 'observed'}


def bluetooth_controllers(value):
    """Read local controllers only; never traverse paired/connected devices."""
    if not isinstance(value, dict) or not isinstance(value.get('SPBluetoothDataType'), list):
        return []
    controllers = []
    for row in value['SPBluetoothDataType'][:16]:
        if not isinstance(row, dict):
            continue
        candidates = [row]
        for name in ('controller_properties', 'local_device', 'local_controller'):
            item = row.get(name)
            if isinstance(item, dict):
                candidates.append(item)
        controller = {}
        for candidate in candidates:
            for key, item in candidate.items():
                name = re.sub(r'[^a-z0-9]', '', str(key).lower())
                if name.startswith('controller'):
                    name = name[len('controller'):]
                elif candidate is row:
                    continue
                field = CONTROLLER_FIELDS.get(name)
                if field and type(item) in (str, int, bool):
                    controller[field] = safe_hardware_text(item) if isinstance(item, str) else item
        if controller:
            controllers.append(controller)
    return controllers


def loaded_drivers(output):
    """Select loaded bundle IDs and versions, excluding paths and UUIDs."""
    entries = []
    for line in output.splitlines():
        match = re.search(r'\b([A-Za-z0-9_.-]{1,128})\s+\(([^()\r\n]{1,48})\)', line)
        if not match or not DRIVERS.search(match[1]):
            continue
        if not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,47}', match[2]):
            continue
        entry = {'bundle_identifier': match[1], 'loaded_version': match[2]}
        if entry not in entries:
            entries.append(entry)
        if len(entries) == 128:
            break
    return entries


def wifi_report(value):
    """Select local AirPort interface fields, never current/nearby networks."""
    if not isinstance(value, dict) or not isinstance(value.get('SPAirPortDataType'), list):
        return unknown('interface_report_unavailable')
    interfaces = []
    for row in value['SPAirPortDataType'][:16]:
        if not isinstance(row, dict):
            continue
        rows = row.get('spairport_airport_interfaces')
        if not isinstance(rows, list):
            continue
        for item in rows[:32]:
            if not isinstance(item, dict):
                continue
            name = item.get('_name')
            if not isinstance(name, str) or not re.fullmatch(r'en\d{1,4}', name):
                continue
            selected = {'interface': name}
            for source, field in (
                    ('spairport_wireless_card_type', 'reported_card_type'),
                    ('spairport_wireless_firmware_version', 'reported_firmware_version'),
                    ('spairport_status_information', 'reported_status')):
                if isinstance(item.get(source), str):
                    selected[field] = safe_hardware_text(item[source])
            # Preserve the profiler's card description verbatim. Its hex pair
            # can describe board/subsystem IDs; do not relabel it as PCI IDs.
            if selected not in interfaces:
                interfaces.append(selected)
    if not interfaces:
        return unknown('interface_fields_unavailable')
    return {'status': 'observed', 'interfaces': interfaces[:32], 'pci_identity_verified': None,
            'complete_inventory': False, 'peer_connectivity_verified': None}


def pci_network_bindings(devices, controllers):
    """Match controller objects to their nearest observed PCI device."""
    if not isinstance(devices, list) or not isinstance(controllers, list):
        return {}
    targets = {row['IORegistryEntryID'] for row in controllers if isinstance(row, dict)
               and type(row.get('IORegistryEntryID')) is int}
    matches = {}
    def identity_for(device):
        identity = {}
        for key, field in (('vendor-id', 'vendor_id'), ('device-id', 'device_id'),
                           ('subsystem-vendor-id', 'subsystem_vendor_id'), ('subsystem-id', 'subsystem_id')):
            raw = device.get(key)
            number = int.from_bytes(raw, 'little') if isinstance(raw, bytes) and len(raw) == 4 else raw
            if type(number) is int and 0 <= number <= 0xffff:
                identity[field] = f'0x{number:04x}'
        return identity if {'vendor_id', 'device_id'} <= identity.keys() else None

    for device in devices[:256]:
        if not isinstance(device, dict):
            continue
        pending = [(device, 0, None, None, 0)]
        visited = 0
        while pending and visited < 512:
            node, depth, identity, provider, hops = pending.pop()
            visited += 1
            # ioreg may include nested matching devices only as children of
            # the outer root. Reset at each PCI device, including invalid IDs,
            # rather than borrowing an upstream bridge's identity.
            if depth == 0 or node.get('IOObjectClass') == 'IOPCIDevice' or ('vendor-id' in node and 'device-id' in node):
                identity = identity_for(node)
                provider, hops = 'IOPCIDevice', 0
            else:
                # Accept a direct client or one verified provider wrapper.
                # A network device downstream of a USB/Thunderbolt bus must
                # not inherit that bus controller's PCI identity.
                object_class = node.get('IOObjectClass', '')
                if (hops >= 2 or node.get('IOProviderClass') != provider or
                        not isinstance(object_class, str) or
                        object_class.startswith(('IOUSB', 'AppleUSB', 'IOThunderbolt', 'AppleThunderbolt'))):
                    identity = None
                provider, hops = object_class, hops + 1
            identifier = node.get('IORegistryEntryID')
            if identity and type(identifier) is int and identifier in targets:
                matches.setdefault(identifier, []).append(identity)
            children = node.get('IORegistryEntryChildren')
            if depth < 6 and isinstance(children, list):
                pending.extend((child, depth + 1, identity, provider, hops)
                               for child in children[:64] if isinstance(child, dict))
    # Conflicting or duplicate observations do not authorize an identity guess.
    return {identifier: rows[0] for identifier, rows in matches.items() if len(rows) == 1}


def network_controllers(value, pci_bindings=None):
    """Associate local interface names with their actual IORegistry controller.

    Ethernet-style Wi-Fi drivers may be absent from AirPort. Keep their binding
    visible without guessing that any particular Ethernet interface is Wi-Fi.
    """
    if not isinstance(value, list):
        return unknown('invalid_registry_report')
    controllers = []
    for row in value[:64]:
        if not isinstance(row, dict):
            continue
        selected = {}
        for source, field in (('IOClass', 'controller_class'),
                              ('IOProviderClass', 'provider_class'),
                              ('CFBundleIdentifier', 'bundle_identifier')):
            item = row.get(source)
            if isinstance(item, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}', item):
                selected[field] = item
        names = set()
        pending = [(row, 0)]
        visited = 0
        while pending and visited < 512:
            node, depth = pending.pop()
            visited += 1
            # Use only direct interface properties, not arbitrary entry names.
            name = node.get('BSD Name')
            if not isinstance(name, str):
                prefix, unit = node.get('IOInterfaceNamePrefix'), node.get('IOInterfaceUnit')
                name = f'{prefix}{unit}' if prefix in ('en', 'awdl', 'llw') and type(unit) is int else None
            if isinstance(name, str) and re.fullmatch(r'(?:en|awdl|llw)\d{1,4}', name):
                names.add(name)
            children = node.get('IORegistryEntryChildren')
            if depth < 3 and isinstance(children, list):
                pending.extend((child, depth + 1) for child in children[:64] if isinstance(child, dict))
        if selected and names:
            pci = (pci_bindings or {}).get(row.get('IORegistryEntryID'))
            if pci:
                selected['pci_identity'] = pci
            controllers.append(dict(selected, interfaces=sorted(names),
                                    fork_provenance_verified=None))
    return {'status': 'observed', 'controllers': controllers, 'complete_inventory': False}


def attach_wifi_bindings(wifi, registry, drivers):
    """Correlate by exact interface/bundle ID; ambiguity remains unknown."""
    for interface in wifi.get('interfaces', []):
        matches = [row for row in registry.get('controllers', [])
                   if interface['interface'] in row['interfaces']]
        interface['controller_binding'] = matches[0] if len(matches) == 1 else None
        binding = interface['controller_binding']
        versions = {row['loaded_version'] for row in drivers.get('entries', [])
                    if binding and row['bundle_identifier'] == binding.get('bundle_identifier')}
        interface['loaded_version'] = next(iter(versions)) if len(versions) == 1 else None
        interface['pci_identity_verified'] = True if binding and binding.get('pci_identity') else None


def graphics_report(value):
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or value.get('probe') != 'host-environment'
            or type(value.get('metal_device_count')) is not int
            or not 0 <= value['metal_device_count'] <= 65535
            or not isinstance(value.get('metal_devices'), list)):
        return unknown('invalid_probe_report')
    h264 = value.get('h264')
    if (not isinstance(h264, dict) or h264.get('sample_profile') != 'Baseline'
            or h264.get('sample_width') != 64 or h264.get('sample_height') != 64):
        return unknown('invalid_probe_report')
    decoders = {}
    for name, required in (('default', False), ('hardware_required', True)):
        item = h264.get(name)
        if (not isinstance(item, dict) or type(item.get('hardware_required')) is not bool
                or item['hardware_required'] is not required
                or type(item.get('fixture_valid')) is not bool
                or type(item.get('frame_decoded')) is not bool
                or 'using_hardware_acceleration' not in item
                or (item.get('using_hardware_acceleration') is not None
                    and type(item['using_hardware_acceleration']) is not bool)):
            return unknown('invalid_probe_report')
        selected = {key: item[key] for key in
                    ('hardware_required', 'fixture_valid', 'frame_decoded', 'using_hardware_acceleration')}
        for key in DECODE_STATUSES:
            if key in item:
                status = item[key]
                if status is not None and (type(status) is not int or not -(1 << 31) <= status < (1 << 31)):
                    return unknown('invalid_probe_report')
                selected[key] = status
        if not item['fixture_valid']:
            return unknown('invalid_probe_fixture')
        if item['frame_decoded'] and any(item.get(key) != 0 for key in DECODE_STATUSES
                                         if key != 'hardware_query_status'):
            return unknown('inconsistent_probe_report')
        gpu_status = item.get('gpu_query_status')
        if gpu_status is not None and (type(gpu_status) is not int or not -(1 << 31) <= gpu_status < (1 << 31)):
            return unknown('invalid_probe_report')
        gpu_name = item.get('gpu_name')
        if gpu_name is not None and (not isinstance(gpu_name, str) or gpu_status != 0):
            return unknown('inconsistent_probe_report')
        selected.update(gpu_query_status=gpu_status,
                        gpu_name=safe_hardware_text(gpu_name) if gpu_name is not None else None)
        decoders[name] = selected
    metal = []
    for item in value['metal_devices'][:16]:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str):
            return unknown('invalid_probe_report')
        selected = {'name': safe_hardware_text(item['name'])}
        for key in ('low_power', 'removable'):
            selected[key] = item.get(key) if type(item.get(key)) is bool else None
        metal.append(selected)
    if len(metal) != min(value['metal_device_count'], 16):
        return unknown('inconsistent_probe_report')
    return {'status': 'observed', 'metal_device_count': value['metal_device_count'],
            'metal_devices': metal, 'h264': {
                'sample_profile': 'Baseline', 'sample_width': 64, 'sample_height': 64, **decoders},
            'native_mirroring_verified': None}


def awdl_report(output, interface='awdl0'):
    if interface not in ('awdl0', 'llw0') or not re.match(re.escape(interface) + r':\s', output):
        return unknown('interface_report_unavailable')
    flags = re.search(r'flags=\d+<([^>]+)>', output)
    return {'status': 'observed', 'interface_present': True,
            'up': 'UP' in flags[1].split(',') if flags else None,
            'running': 'RUNNING' in flags[1].split(',') if flags else None,
            'ipv6_configured': bool(re.search(r'^\s+inet6\s', output, re.M)),
            'link_local_ipv6': bool(re.search(r'^\s+inet6\s+fe80:', output, re.M | re.I)),
            'peer_connectivity_verified': None}


def sip_report(output):
    headline = re.search(r'System Integrity Protection status:\s*([^\r\n]+)', output, re.I)
    if not headline:
        return unknown('status_unavailable')
    text = headline[1].lower()
    if 'custom configuration' in text:
        state = 'custom'
    elif text.strip(' .') == 'enabled':
        state = 'fully_enabled'
    elif text.strip(' .') == 'disabled':
        state = 'disabled'
    else:
        return unknown('status_unavailable')
    return {'status': 'observed', 'state': state,
            'native_support_verified': None}


def inspect_host_environment(root=ROOT):
    """Bound independent reads; return observations independently of readiness."""
    report = {'schema_version': 1, 'read_only': True,
              'native_mirroring_verified': None, 'daily_use_verified': None}
    if sys.platform != 'darwin':
        report.update({name: unknown('platform_unavailable') for name in
                       ('host', 'graphics', 'bluetooth', 'wifi', 'network_controllers', 'pci_inventory',
                        'loaded_drivers', 'awdl', 'llw', 'sip')})
        return report
    commands = {
        'os': (['/usr/bin/sw_vers'], 5),
        'model': (['/usr/sbin/sysctl', '-n', 'hw.model'], 5),
        'graphics': ([str(Path(root) / 'build/inspector'), '--environment'], 15),
        'bluetooth': (['/usr/sbin/system_profiler', '-json', '-timeout', '10', 'SPBluetoothDataType'], 15),
        'wifi': (['/usr/sbin/system_profiler', '-json', '-timeout', '10', 'SPAirPortDataType'], 15),
        'network_controllers': (['/usr/sbin/ioreg', '-a', '-l', '-r', '-c', 'IONetworkController', '-d', '3'], 5),
        'pci_inventory': (['/usr/sbin/ioreg', '-a', '-l', '-r', '-c', 'IOPCIDevice', '-d', '6'], 5),
        'loaded_drivers': (['/usr/bin/kmutil', 'showloaded', '--list-only'], 12),
        'awdl': (['/sbin/ifconfig', 'awdl0'], 5),
        'llw': (['/sbin/ifconfig', 'llw0'], 5),
        'sip': (['/usr/bin/csrutil', 'status'], 5),
    }
    with ThreadPoolExecutor(max_workers=4) as executor:
        pending = {name: executor.submit(command, *arguments) for name, arguments in commands.items()}
        results = {name: future.result() for name, future in pending.items()}
    os_text, host = results['os']
    if os_text is not None:
        for key, label, pattern in (('os_version', 'ProductVersion', r'\d+(?:\.\d+){1,2}'),
                                    ('os_build', 'BuildVersion', r'\d+[A-Z]\d+[a-z]?')):
            match = re.search(r'^' + label + r':\s*(' + pattern + r')\s*$', os_text, re.M)
            host[key] = match[1] if match else None
    model_text, _ = results['model']
    host['model'] = model_text.strip() if model_text and re.fullmatch(
        r'[A-Za-z][A-Za-z0-9]{0,31}\d+,\d+\s*', model_text) else None
    architecture = platform.machine()
    host['architecture'] = architecture if architecture in ('x86_64', 'arm64') else None
    report['host'] = host
    bindings = {}
    raw_pci, pci_status = results['pci_inventory']
    raw_controllers, _ = results['network_controllers']
    if raw_pci is not None:
        try:
            devices = plistlib.loads(raw_pci.encode())
            if not isinstance(devices, list):
                raise ValueError('Invalid PCI inventory')
            if raw_controllers is not None:
                bindings = pci_network_bindings(devices, plistlib.loads(raw_controllers.encode()))
            pci_status = {'status': 'observed', 'matched_controller_count': len(bindings)}
        except (ValueError, TypeError, ExpatError):
            pci_status = unknown('invalid_registry_report')
    report['pci_inventory'] = dict(pci_status, complete_inventory=False)
    for name, parse in (('graphics', graphics_report), ('bluetooth', bluetooth_controllers),
                        ('wifi', wifi_report), ('network_controllers', lambda value: network_controllers(value, bindings))):
        raw, observation = results[name]
        if raw is not None:
            try:
                parsed = parse(plistlib.loads(raw.encode()) if name == 'network_controllers' else json.loads(raw))
                if name == 'bluetooth':
                    observation = {'status': 'observed', 'controllers': parsed} if parsed else unknown('controller_fields_unavailable')
                else:
                    observation = parsed
            except (ValueError, TypeError, ExpatError):
                observation = unknown('invalid_registry_report' if name == 'network_controllers' else 'invalid_json')
        report[name] = observation
    raw, drivers = results['loaded_drivers']
    if raw is None:
        raw, drivers = command(['/usr/sbin/kextstat', '-l'], 8)
        drivers['source'] = 'kextstat'
    else:
        drivers['source'] = 'kmutil'
    if raw is not None:
        drivers['entries'] = loaded_drivers(raw)
    drivers['complete_inventory'] = False  # Codeless/injected/user-space drivers may not appear.
    report['loaded_drivers'] = drivers
    attach_wifi_bindings(report['wifi'], report['network_controllers'], drivers)
    for name, parse in (('awdl', awdl_report), ('llw', lambda raw: awdl_report(raw, 'llw0')), ('sip', sip_report)):
        raw, observation = results[name]
        report[name] = parse(raw) if raw is not None else observation
    return report
