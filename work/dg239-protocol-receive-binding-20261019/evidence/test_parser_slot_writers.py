"""Stop before effects; adversarial pointers are synthetic, not observed objects."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_slot_writers import PINS, build
from receive_slices import BytesState, CallBarrier, Sample, run


class ParserSlotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def test_artifact_matches_original_sample(self):
        artifact = Path(__file__).resolve().parents[1] / "report/parser-slot-writers.json"
        self.assertEqual(build(self.sample), json.loads(artifact.read_text()))

    def test_arguments_stop_before_store_or_lifetime_effects(self):
        for va, value in ((0x100843FB0, 0), (0x100849B48, 0x6000)):
            state = BytesState({"x19": 0x1000})
            state.put(0x2160, 0x4000)
            state.put(0x1370, 0x6000)
            state.put(0x4000, 0x7000)
            with self.assertRaises(CallBarrier) as caught:
                run(self.sample, va, bytes.fromhex(PINS[va]), state)
            self.assertEqual(caught.exception.pc, va + 8)
            self.assertEqual((state.reg("x0"), state.reg("x1")), (0x4000, value))
            self.assertEqual(state.get(0x4000), 0x7000)
            self.assertFalse(any(e["kind"] == "write" for e in state.events))

    def test_each_window_and_import_mutation_is_rejected(self):
        original = self.sample.window
        for va in PINS:
            def changed(address, size):
                result = original(address, size)
                if address == va:
                    result["bytes"] = "00" + result["bytes"][2:]
                return result
            with patch.object(self.sample, "window", side_effect=changed):
                with self.assertRaises(ValueError):
                    build(self.sample)
        wrong = dict(self.sample.stub_symbol(0x100AE01F8), name="_objc_release")
        with patch.object(self.sample, "stub_symbol", return_value=wrong):
            with self.assertRaises(ValueError):
                build(self.sample)


if __name__ == "__main__":
    unittest.main()
