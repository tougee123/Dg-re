import copy
import random
import unittest

from binary_evidence import ROOT, Sample
from callback_bytes import MASK, build as callback_build, count
from parser_stages import SOURCES, build, validate_row


class ProtocolEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()
        cls.report = build(cls.sample, [(p, (ROOT / p).read_bytes()) for p in SOURCES])

    def test_local_observations_not_endpoint_proof(self):
        rows = [r for s in self.report["sources"] for r in s["rows"]]
        self.assertEqual(len(rows), 30)
        self.assertEqual(len({r["unslid_caller"] for r in rows}), 7)
        self.assertTrue(all(r["endpoint"] is None and not r["wire_response_proven"] for r in rows))

    def test_each_invalid_field_is_rejected_individually(self):
        original = self.report["sources"][0]["rows"][0]
        for field, value in [("unslid_caller", "0x1006618a4"),
                             ("selector_observed", "dataWithBytes:length:"),
                             ("hook_declaration", "different hook"), ("hook_line", 0),
                             ("options", "0x0"), ("error_out", "0x1"),
                             ("complete_call", False), ("source_call_errors", 1),
                             ("return_line", 0), ("event_tid", -1)]:
            with self.subTest(field=field):
                row = copy.deepcopy(original)
                row[field] = value
                self.assertFalse(validate_row(row, self.report["windows"]))

    def test_missing_raw_hook_is_rejected(self):
        for path in SOURCES:
            raw = (ROOT / path).read_bytes()
            lines = raw.splitlines(keepends=True)
            del lines[3]
            with self.assertRaisesRegex(ValueError, "hook declaration"):
                build(self.sample, [(path, b"".join(lines))])

    def test_truncated_original_byte_window_rejected(self):
        class Truncated:
            def window(inner, va, size):
                window = self.sample.window(va, size)
                window["bytes"] = window["bytes"][:-2]
                return window
        with self.assertRaises(ValueError):
            build(Truncated(), [])

    def test_callback_bytes_and_selectors(self):
        self.assertEqual(len(callback_build(self.sample)["windows"]), 3)

    def test_count_boundaries_and_deterministic_random(self):
        boundary = [0, 1, 2, 15, 16, 63, 64, 65, 16384, (1 << 63) - 1, 1 << 63, MASK]
        pairs = [(a, b) for a in boundary for b in boundary]
        rng = random.Random(239)
        pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4096)]
        for a, b in pairs:
            self.assertEqual(count(a, b), a * b & MASK)

    def test_wrong_orn_complement_mutation_detected(self):
        a, b = 1, 2
        wrong = ((a & ~b) * (~(a | b) & MASK) + (a | b) * (a & b)) & MASK
        self.assertNotEqual(wrong, a * b & MASK)
        self.assertEqual(count(a, b), 2)


if __name__ == "__main__":
    unittest.main()
