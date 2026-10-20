import unittest

import lief

from bind_provenance import EXPECTED, MASK, Sample, build, decode, metadata


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


class BindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def small(self, suffix):
        return decode(b'\x11\x40_symbol\0\x51\x70\x00' + suffix,
                      [('data', 0x1000, 0x100)], ['library'])

    def test_independent_lief_comparison(self):
        result = build(self.sample)
        binary = lief.MachO.parse(list(self.sample.raw)).at(0)
        for record in result['bindings']:
            matches = [b for b in binary.bindings if b.address == int(record['va'], 16)]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].symbol.name, record['symbol'])
            self.assertEqual(matches[0].library.name, record['library'])
            self.assertEqual(matches[0].library_ordinal, record['ordinal'])
        self.assertFalse(result['live_target_proven'])
        self.assertFalse(result['same_transaction_decoder_proven'])

    def test_backwards_address_wrap(self):
        records = self.small(b'\x90\x80' + uleb(MASK - 7) + b'\x90\x00')
        self.assertEqual([r['va'] for r in records], ['0x1000', '0x1000'])

    def test_repeat_and_skips(self):
        records = self.small(b'\xc0\x03\x08\xa0\x08\xb1\x00')
        self.assertEqual([r['va'] for r in records],
                         ['0x1000', '0x1010', '0x1020', '0x1030', '0x1040'])

    def test_signed_addend(self):
        self.assertEqual(self.small(b'\x60\x7f\x90\x00')[0]['addend'], -1)

    def test_reject_invalid_streams(self):
        cases = [b'\xd0\x00', b'\x80\x80', b'\x70\x80\x02\x90\x00',
                 b'\x90', b'\x00\x90', b'\x52\x90\x00', b'\x7f\x00\x90\x00']
        for raw in cases:
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                self.small(raw)

    def test_symbol_mutation_is_detected(self):
        _, _, (offset, length) = metadata(self.sample.raw)
        for symbol in EXPECTED.values():
            changed = bytearray(self.sample.raw)
            position = changed.find(symbol.encode() + b'\0', offset, offset + length)
            self.assertGreaterEqual(position, offset)
            changed[position] = ord('X')
            original = self.sample.raw
            try:
                self.sample.raw = bytes(changed)
                with self.assertRaisesRegex(ValueError, 'unexpected binding'):
                    build(self.sample)
            finally:
                self.sample.raw = original

    def test_missing_bind_is_detected(self):
        record = build(self.sample)['bindings'][0]
        changed = bytearray(self.sample.raw)
        position = record['bind_opcode_fileoff']
        changed[position] = 0xD0
        original = self.sample.raw
        try:
            self.sample.raw = bytes(changed)
            with self.assertRaises(ValueError):
                build(self.sample)
        finally:
            self.sample.raw = original


if __name__ == '__main__':
    unittest.main()
