import json
import plistlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from hardware import (awdl_report, bluetooth_controllers, command, graphics_report,
                      inspect_host_environment, loaded_drivers, sip_report, DECODE_STATUSES,
                      wifi_report, network_controllers, attach_wifi_bindings, pci_network_bindings)


def fixture_graphics():
    decoder = {key: 0 for key in DECODE_STATUSES}
    decoder.update(fixture_valid=True, frame_decoded=True, using_hardware_acceleration=True)
    return {'schema_version': 1, 'probe': 'host-environment',
            'metal_device_count': 1, 'metal_devices': [{
                'name': 'Fixture GPU', 'low_power': False, 'removable': False}],
            'h264': {'sample_profile': 'Baseline', 'sample_width': 64, 'sample_height': 64,
                     'default': dict(decoder, hardware_required=False),
                     'hardware_required': dict(decoder, hardware_required=True)}}


class HostObservationTests(unittest.TestCase):
    def test_pci_binding_requires_exact_object_and_does_not_use_parent_bridge_ids(self):
        def device(vendor, product, children):
            return {'vendor-id': vendor.to_bytes(4, 'little'), 'device-id': product.to_bytes(4, 'little'),
                    'IORegistryEntryChildren': children, 'IORegistryEntryName': 'private-pci-path'}
        controller = {'IORegistryEntryID': 123, 'IOClass': 'FixtureController',
                      'IOProviderClass': 'IOPCIDevice',
                      'IORegistryEntryChildren': [{'BSD Name': 'en2'}]}
        card = device(0x14c3, 0x7961, [controller])
        bridge = device(0x8086, 0x1234, [card])
        bindings = pci_network_bindings([bridge], [controller])
        self.assertEqual(bindings, {123: {'vendor_id': '0x14c3', 'device_id': '0x7961'}})
        report = network_controllers([controller], bindings)
        self.assertEqual(report['controllers'][0]['pci_identity'], bindings[123])
        self.assertNotIn('123', json.dumps(report))
        self.assertNotIn('private', json.dumps(report))
        self.assertEqual(pci_network_bindings([card, card], [controller]), {})
        self.assertEqual(pci_network_bindings([bridge, card], [controller]), {})
        self.assertEqual(pci_network_bindings([device(0x10000, 1, [controller])], [controller]), {})
        self.assertEqual(pci_network_bindings([device(1, 2, [device(0x10000, 1, [controller])])], [controller]), {})
        self.assertEqual(pci_network_bindings([device(1, 2, [{'IORegistryEntryID': 456}])], [controller]), {})
        usb_controller = dict(controller, IOProviderClass='IOUSBHostDevice')
        usb = {'IOObjectClass': 'IOUSBHostDevice', 'IOProviderClass': 'IOPCIDevice',
               'IORegistryEntryChildren': [usb_controller]}
        self.assertEqual(pci_network_bindings([device(1, 2, [usb])], [usb_controller]), {})
        wrapped = dict(controller, IOProviderClass='FixtureWrapper')
        wrapper = {'IOObjectClass': 'FixtureWrapper', 'IOProviderClass': 'IOPCIDevice',
                   'IORegistryEntryChildren': [wrapped]}
        self.assertEqual(pci_network_bindings([device(0x14c3, 0x7961, [wrapper])], [wrapped]), bindings)
        wrapper['IOProviderClass'] = 'UnverifiedProvider'
        self.assertEqual(pci_network_bindings([device(1, 2, [wrapper])], [wrapped]), {})

    def test_wifi_selects_card_fields_without_network_inventories(self):
        raw = {'SPAirPortDataType': [{'spairport_airport_interfaces': [{
            '_name': 'en2', 'spairport_wireless_card_type': 'Fixture (0x14C3, 0x7961)',
            'spairport_wireless_firmware_version': 'Fixture 1.2',
            'spairport_status_information': 'spairport_status_connected',
            'spairport_current_network_information': {'_name': 'private-ssid'},
            'spairport_airport_other_local_wireless_networks': ['private-nearby'],
            'spairport_hardware_address': 'aa:bb:cc:dd:ee:ff'},
            {'_name': 'private-device-name', 'spairport_wireless_card_type': 'private-card'},
            {'_name': 'awdl0'}]}]}
        value = wifi_report(raw)
        self.assertEqual(value['interfaces'], [{
            'interface': 'en2', 'reported_card_type': 'Fixture (0x14C3, 0x7961)',
            'reported_firmware_version': 'Fixture 1.2',
            'reported_status': 'spairport_status_connected'}])
        self.assertIsNone(value['pci_identity_verified'])
        self.assertFalse(value['complete_inventory'])
        self.assertNotIn('private', json.dumps(value))
        self.assertNotIn('aa:bb', json.dumps(value))
        for raw in (None, {}, {'SPAirPortDataType': []}, {'SPAirPortDataType': [None]}):
            self.assertEqual(wifi_report(raw)['status'], 'unknown')

    def test_registry_bindings_preserve_ethernet_style_interfaces_without_vendor_guesses(self):
        value = network_controllers([{
            'IOClass': 'FixtureController', 'IOProviderClass': 'IOPCIDevice',
            'CFBundleIdentifier': 'example.Driver', 'private-property': 'private-secret',
            'IORegistryEntryChildren': [
                {'BSD Name': 'en2', 'IOMACAddress': b'private-address'},
                {'IOInterfaceNamePrefix': 'en', 'IOInterfaceUnit': 2},
                {'BSD Name': 'awdl0'}, {'IORegistryEntryName': 'en9'},
                {'BSD Name': 'private-device-name'}]}])
        self.assertEqual(value['controllers'][0]['interfaces'], ['awdl0', 'en2'])
        self.assertIsNone(value['controllers'][0]['fork_provenance_verified'])
        self.assertNotIn('private', json.dumps(value))
        wifi = {'interfaces': [{'interface': 'en2'}, {'interface': 'en9'}]}
        drivers = {'entries': [{'bundle_identifier': 'example.Driver', 'loaded_version': '1.2'}]}
        attach_wifi_bindings(wifi, value, drivers)
        self.assertEqual(wifi['interfaces'][0]['loaded_version'], '1.2')
        self.assertEqual(wifi['interfaces'][0]['controller_binding']['controller_class'], 'FixtureController')
        self.assertIsNone(wifi['interfaces'][1]['controller_binding'])
        value['controllers'] *= 2
        attach_wifi_bindings(wifi, value, drivers)
        self.assertIsNone(wifi['interfaces'][0]['controller_binding'])
        self.assertIsNone(wifi['interfaces'][0]['loaded_version'])

    def test_graphics_gpu_name_requires_successful_property_query(self):
        value = fixture_graphics()
        value['h264']['default'].update(gpu_query_status=0, gpu_name='Fixture GPU', registry_id='private-id')
        selected = graphics_report(value)['h264']['default']
        self.assertEqual(selected['gpu_name'], 'Fixture GPU')
        self.assertNotIn('private', json.dumps(selected))
        value['h264']['default']['gpu_query_status'] = -1
        self.assertEqual(graphics_report(value)['status'], 'unknown')
        value['h264']['default']['gpu_name'] = None
        self.assertEqual(graphics_report(value)['h264']['default']['gpu_query_status'], -1)

    def test_bluetooth_ignores_paired_devices_addresses_and_names(self):
        report = {'SPBluetoothDataType': [{
            'controller_properties': {
                'controller_chipset': 'BCM_20702A3', 'controller_firmwareVersion': 'v14 c5681',
                'controller_transport': 'USB', 'controller_address': 'aa:bb:cc:dd:ee:ff',
                'controller_name': 'Private Mac'},
            'device_connected': {'Private iPhone': {
                'controller_chipset': 'private-pairing', 'controller_properties': {'chipset': 'private-device'}}},
            'device_paired': ['private-inventory']}]}
        selected = bluetooth_controllers(report)
        self.assertEqual(selected, [{
            'chipset': 'BCM_20702A3', 'firmware_version': 'v14 c5681', 'transport': 'USB'}])
        self.assertNotIn('Private', json.dumps(selected))
        self.assertNotIn('aa:bb', json.dumps(selected))

    def test_older_controller_layout_and_malformed_reports(self):
        report = {'SPBluetoothDataType': [{'local_device': {
            'lmp_version': '0x6', 'manufacturer': 'Broadcom',
            'name': 'private-name', 'address': 'private-address'}}]}
        self.assertEqual(bluetooth_controllers(report), [{'lmp_version': '0x6', 'manufacturer': 'Broadcom'}])
        for value in (None, [], {}, {'SPBluetoothDataType': 'bad'}, {'SPBluetoothDataType': [None]}):
            self.assertEqual(bluetooth_controllers(value), [])

    def test_driver_list_excludes_unrelated_kexts_paths_and_uuids(self):
        output = (
            '11 0 0xffffff00 0x1000 0x1000 as.vit9696.BlueToolFixup (2.6.9) PRIVATE-UUID <1 2>\n'
            '12 0 0xffffff00 0x1000 0x1000 as.vit9696.Lilu (1.7.1) ANOTHER-UUID <1>\n'
            '13 0 com.example.privateDriver (1.0) secret\n'
            '14 0 com.example.IntelBluetoothFirmware (private-secret) secret\n'
            '/Users/private-path/Library/Example\n')
        self.assertEqual(loaded_drivers(output), [
            {'bundle_identifier': 'as.vit9696.BlueToolFixup', 'loaded_version': '2.6.9'},
            {'bundle_identifier': 'as.vit9696.Lilu', 'loaded_version': '1.7.1'}])

    def test_metal_and_real_frame_decoding_are_distinct_observations(self):
        fixture = fixture_graphics()
        fixture['h264']['hardware_required'].update(
            session_status=-12906, frame_decoded=False, using_hardware_acceleration=None)
        for key in ('submit_status', 'wait_status', 'output_status'):
            fixture['h264']['hardware_required'].pop(key)
        report = graphics_report(fixture)
        self.assertEqual(report['metal_device_count'], 1)
        self.assertTrue(report['h264']['default']['frame_decoded'])
        self.assertFalse(report['h264']['hardware_required']['frame_decoded'])
        self.assertIsNone(report['h264']['hardware_required']['using_hardware_acceleration'])
        self.assertIsNone(report['native_mirroring_verified'])

    def test_invalid_fixture_and_inconsistent_success_are_unknown(self):
        for change in ({'fixture_valid': False}, {'frame_decoded': 1},
                       {'output_status': -12909}, {'session_status': True}):
            with self.subTest(change=change):
                fixture = fixture_graphics()
                fixture['h264']['default'].update(change)
                self.assertEqual(graphics_report(fixture)['status'], 'unknown')
        fixture = fixture_graphics()
        del fixture['h264']['default']['using_hardware_acceleration']
        self.assertEqual(graphics_report(fixture)['status'], 'unknown')
        self.assertEqual(graphics_report(None)['status'], 'unknown')

    def test_graphics_filters_nonhardware_fields(self):
        fixture = fixture_graphics()
        fixture.update(certificate='secret', paired_devices=['private'])
        fixture['metal_devices'][0].update(registry_id='unique-id', address='private-address')
        fixture['h264']['default']['sample'] = 'private-frame'
        self.assertNotIn('private', json.dumps(graphics_report(fixture)))
        self.assertNotIn('unique-id', json.dumps(graphics_report(fixture)))

    def test_awdl_report_retains_flags_without_addresses_or_connectivity_claims(self):
        output = ('awdl0: flags=8943<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n'
                  '\tether aa:bb:cc:dd:ee:ff\n\tinet6 fe80::private%awdl0 prefixlen 64\n')
        report = awdl_report(output)
        self.assertTrue(report['up'])
        self.assertTrue(report['ipv6_configured'])
        self.assertTrue(report['link_local_ipv6'])
        self.assertIsNone(report['peer_connectivity_verified'])
        self.assertNotIn('private', json.dumps(report))
        self.assertNotIn('aa:bb', json.dumps(report))
        self.assertEqual(awdl_report('unknown')['status'], 'unknown')
        self.assertTrue(awdl_report(output.replace('awdl0', 'llw0'), 'llw0')['interface_present'])
        self.assertEqual(awdl_report(output, 'llw0')['status'], 'unknown')

    def test_sip_custom_is_not_treated_as_fully_enabled_or_verified(self):
        for text, state in (
            ('enabled.', 'fully_enabled'), ('disabled.', 'disabled'),
            ('unknown (Custom Configuration).', 'custom'),
            ('disabled (Custom Configuration).', 'custom')):
            report = sip_report('System Integrity Protection status: ' + text)
            self.assertEqual(report['state'], state)
            self.assertIsNone(report['native_support_verified'])
        self.assertEqual(sip_report('permission denied')['status'], 'unknown')

    def test_errors_never_copy_stderr_or_partial_command_output(self):
        failures = [OSError('/Users/private-path'),
                    subprocess.TimeoutExpired(['tool'], 1, output='private-output', stderr='private-error')]
        for error in failures:
            with patch('hardware.subprocess.run', side_effect=error):
                raw, status = command(['tool'], 1)
                self.assertIsNone(raw)
                self.assertEqual(status['status'], 'unknown')
                self.assertNotIn('private', json.dumps(status))
        with patch('hardware.subprocess.run', return_value=subprocess.CompletedProcess(
                ['tool'], 1, 'private-output', 'private-error')):
            self.assertEqual(command(['tool'], 1),
                             (None, {'status': 'unknown', 'reason': 'command_failed', 'exit_code': 1}))

    def test_inspection_is_bounded_optional_and_has_safe_fallbacks(self):
        def run(arguments, timeout):
            self.assertLessEqual(timeout, 15)
            self.assertNotIn('sudo', arguments)
            if '--environment' in arguments:
                return json.dumps(fixture_graphics()), {'status': 'observed'}
            if arguments[0].endswith('sw_vers'):
                return 'ProductName:\tmacOS\nProductVersion:\t15.7.2\nBuildVersion:\t24G325\n', {'status': 'observed'}
            if arguments[-1] == 'hw.model':
                return 'iMac20,2\n', {'status': 'observed'}
            if 'SPBluetoothDataType' in arguments:
                return json.dumps({'SPBluetoothDataType': [{'controller_properties': {
                    'controller_chipset': 'BCM_20702A3', 'controller_address': 'private-address'}}]}), {'status': 'observed'}
            if 'SPAirPortDataType' in arguments:
                return json.dumps({'SPAirPortDataType': [{'spairport_airport_interfaces': [
                    {'_name': 'en2', 'spairport_current_network_information': 'private-ssid'}]}]}), {'status': 'observed'}
            if arguments[0].endswith('ioreg'):
                return plistlib.dumps([{'IOClass': 'FixtureController', 'CFBundleIdentifier': 'as.vit9696.BlueToolFixup',
                    'IORegistryEntryChildren': [{'BSD Name': 'en2'}]}]).decode(), {'status': 'observed'}
            if arguments[0].endswith('kmutil'):
                return None, {'status': 'unknown', 'reason': 'command_failed'}
            if arguments[0].endswith('kextstat'):
                return '1 0 as.vit9696.BlueToolFixup (2.6.9) PRIVATE-UUID', {'status': 'observed'}
            return None, {'status': 'unknown', 'reason': 'tool_unavailable'}
        with patch('hardware.sys.platform', 'darwin'), patch('hardware.platform.machine', return_value='x86_64'), \
                patch('hardware.command', side_effect=run) as observed:
            report = inspect_host_environment('/fixture')
        self.assertEqual(observed.call_count, 12)
        self.assertEqual(report['host']['os_build'], '24G325')
        self.assertEqual(report['host']['model'], 'iMac20,2')
        self.assertEqual(report['loaded_drivers']['source'], 'kextstat')
        self.assertFalse(report['loaded_drivers']['complete_inventory'])
        self.assertEqual(report['awdl']['status'], 'unknown')
        self.assertEqual(report['llw']['status'], 'unknown')
        self.assertEqual(report['wifi']['interfaces'][0]['loaded_version'], '2.6.9')
        self.assertNotIn('private', json.dumps(report).lower())
        self.assertIsNone(report['native_mirroring_verified'])

    def test_malformed_registry_does_not_discard_other_observations(self):
        for raw in ('not a plist', '<?xml version="1.0"?><plist><array><dict>'):
            with self.subTest(raw=raw):
                def run(arguments, timeout):
                    if arguments[0].endswith('ioreg'):
                        return raw, {'status': 'observed'}
                    return None, {'status': 'unknown', 'reason': 'timeout'}
                with patch('hardware.sys.platform', 'darwin'), patch('hardware.command', side_effect=run):
                    value = inspect_host_environment('/fixture')
                self.assertEqual(value['network_controllers']['reason'], 'invalid_registry_report')
                self.assertEqual(value['pci_inventory']['reason'], 'invalid_registry_report')
                self.assertEqual(value['wifi']['reason'], 'timeout')

    def test_other_platforms_do_not_run_host_commands(self):
        with patch('hardware.sys.platform', 'linux'), patch('hardware.command') as observed:
            report = inspect_host_environment('/fixture')
        observed.assert_not_called()
        self.assertEqual(report['graphics']['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
