import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from wire import nodes, platform_ltk, wrap

TAGS = (0x81, 0x85, 0x86, 0x82, 0x83, 0x84)


def fixture(size=700, tags=TAGS):
    for payload in range(max(0, size - 80), size):
        raw = wrap(0x30, b''.join(wrap(tag, b'x' * (payload if index == 1 else 1))
                                  for index, tag in enumerate(tags)))
        if len(raw) == size:
            return raw
    raise AssertionError('Cannot construct fixture of size ' + str(size))


class WireBoundaryTests(unittest.TestCase):
    def adapt(self, raw, platform=3):
        encoded, proof = platform_ltk(base64.b64encode(raw).decode(), platform)
        return base64.b64decode(encoded), proof

    def test_maximum_output_is_checked_after_platform_tag_is_appended(self):
        modified, proof = self.adapt(fixture(65533))
        self.assertEqual(len(modified), 65536)
        self.assertEqual(proof['wire_bytes'], 65536)
        for size in (65534, 65535, 65536):
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, 'native key limit'):
                self.adapt(fixture(size))

    def test_existing_fields_are_preserved_at_der_length_boundaries(self):
        for size in (512, 513, 700, 1024, 65532, 65533):
            with self.subTest(size=size):
                original = fixture(size)
                modified, proof = self.adapt(original)
                parent, = nodes(original)
                updated_parent, = nodes(modified)
                self.assertEqual(modified[updated_parent[2]:updated_parent[3]],
                                 original[parent[2]:parent[3]] + b'\x87\x01\x03')
                self.assertTrue(proof['original_fields_byte_identical'])
                self.assertFalse(proof['stock_phone_acceptance_verified'])

    def test_invalid_sizes_platforms_and_unreviewed_layouts_are_refused(self):
        for size in (511, 65537):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.adapt(fixture(size))
        for platform in (0, 1, 2, 4):
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                self.adapt(fixture(), platform)
        for tags in (TAGS[::-1], TAGS[:-1], TAGS + (0x87,), (0x81,) + TAGS[1:-1] + (0x85,)):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                self.adapt(fixture(tags=tags))

    def test_malformed_der_and_base64_cannot_publish_a_wire_key(self):
        raw = fixture()
        for malformed in (raw[:-1], raw + b'\x30\x00', b'\x30\x80' + raw[2:],
                          b'\x30\x85\x00\x00\x00\x02\x00' + raw[7:]):
            with self.subTest(prefix=malformed[:8]), self.assertRaises(ValueError):
                self.adapt(malformed)
        with self.assertRaises(ValueError):
            platform_ltk('!!!!', 3)


if __name__ == '__main__':
    unittest.main()
