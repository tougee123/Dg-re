import unittest

from binary_evidence import Sample
from callback_gate import MASK, PINS, build, run_local, table_memory


class CallbackGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def predicate(self, raw=None, words=None):
        frame, slot = 0x200000000, 0x400000000
        memory = {frame + 0x3DF0: 0x600000000, frame + 0x3E08: 0x300000000,
                  frame + 0x3588: 0x500000000, frame + 0x3590: slot,
                  frame + 0x3598: 0, slot: 0}
        memory.update(words or {})
        return run_local(self.sample, 0x1005CAEAC,
                         raw if raw is not None else bytes.fromhex(PINS[0x1005CAEAC]),
                         {"x19": frame}, memory)

    def test_separate_epochs_can_select_opposite_arms(self):
        cases = build(self.sample)["local_cases"]
        self.assertEqual([(c["first_index"], c["second_index"]) for c in cases],
                         [(0, 0), (0, 1), (1, 0), (1, 1)])
        self.assertTrue(all("NOT a sequential" in c["meaning"] for c in cases))

    def test_slot_mutation_reads_different_pointee(self):
        raw = bytes.fromhex(PINS[0x1005CAEAC])
        self.assertEqual(raw[8:12].hex(), "6aca5af9")
        mutant = raw[:8] + bytes.fromhex("6ac25af9") + raw[12:]
        frame, other = 0x200000000, 0x700000000
        words = {frame + 0x3580: other, other: MASK}
        self.assertEqual(self.predicate(words=words)["words"][frame + 0x359C], 0)
        self.assertEqual(self.predicate(mutant, words)["words"][frame + 0x359C], 1)

    def test_cset_condition_mutation_changes_result(self):
        raw = bytes.fromhex(PINS[0x1005CAEAC])
        self.assertEqual(raw.count(bytes.fromhex("ea079f1a")), 1)
        mutant = raw.replace(bytes.fromhex("ea079f1a"), bytes.fromhex("ea179f1a"))
        frame = 0x200000000
        self.assertEqual(self.predicate()["words"][frame + 0x359C], 0)
        self.assertEqual(self.predicate(mutant)["words"][frame + 0x359C], 1)

    def test_dispatch_uses_table_not_assumed_target(self):
        frame, context, table = 0x200000000, 0x300000000, 0x101570F58
        words = {frame + 0x3E08: context, frame + 0x359C: 0,
                 context + 0x1100: table} | table_memory(self.sample, table)
        raw = bytes.fromhex(PINS[0x1005FBB74])
        before = run_local(self.sample, 0x1005FBB74, raw, {"x19": frame}, words)
        words[table], words[table + 8] = words[table + 8], words[table]
        after = run_local(self.sample, 0x1005FBB74, raw, {"x19": frame}, words)
        self.assertEqual(before["branch"], 0x1005F7BB8)
        self.assertEqual(after["branch"], 0x1005E8588)

    def test_missing_memory_and_external_call_fail_closed(self):
        with self.assertRaises(KeyError):
            run_local(self.sample, 0x1005CAEAC, bytes.fromhex(PINS[0x1005CAEAC]),
                      {"x19": 0x200000000}, {})
        with self.assertRaisesRegex(ValueError, "unsupported instruction bl"):
            run_local(self.sample, 0x1005CAE98, self.sample.read(0x1005CAE98, 4), {}, {})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.predicate(bytes.fromhex(PINS[0x1005CAEAC])[:-1])

    def test_changed_original_bytes_rejected(self):
        sample = self.sample

        class Changed:
            def window(self, va, size):
                window = sample.window(va, size)
                if va == 0x1005CAEAC:
                    window["bytes"] = "00" + window["bytes"][2:]
                return window

        with self.assertRaisesRegex(ValueError, "callback bytes changed"):
            build(Changed())

    def test_import_identity_and_invalid_stub(self):
        self.assertEqual(self.sample.stub_symbol(0x100AE01F8)["name"], "_objc_storeStrong")
        self.assertEqual(self.sample.stub_symbol(0x100AE00E4)["name"], "_objc_autoreleaseReturnValue")
        for va in [0x100AE01FC, 0x1005CAE98]:
            with self.assertRaises(ValueError):
                self.sample.stub_symbol(va)

    def test_wrong_import_symbol_rejected(self):
        sample = self.sample

        class Changed:
            def __getattr__(self, key):
                return getattr(sample, key)

            def stub_symbol(self, va):
                entry = sample.stub_symbol(va)
                entry["name"] = "_different"
                return entry

        with self.assertRaisesRegex(ValueError, "unexpected imported symbol"):
            build(Changed())


if __name__ == "__main__":
    unittest.main()
