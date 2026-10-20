"""Synthetic preconditions for pinned linear slices, never external return stubs."""
import json
import random
import unittest
from pathlib import Path
from unittest.mock import patch

from receive_slices import BytesState, CallBarrier, MASK, PINS, Sample, build, import_slot, run


class ReceiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def execute(self, va, state, start=0, end=None):
        raw = bytes.fromhex(PINS[va])[start:end]
        return run(self.sample, va + start, raw, state)

    def count_state(self, a, b):
        return BytesState({"x0": 0x2000, "x11": 0x2100, "x12": 0x2200,
                           "x14": 0x2300, "x10": 0x2400, "x19": 0x1000,
                           "x17": 0x4000, "x16": a, "x15": b, "x13": 0x5000})

    def copy_state(self, index=2, old=9, src=0x5000, dst=0x6000):
        state = BytesState({"x19": 0x1000, "x10": 0x2100, "x11": 0x2200,
                            "x12": 0x2300, "x13": 0x2400})
        for offset, slot in ((0xA0, 0x2100), (0x90, 0x2200), (0x30, 0x2300), (0xA8, 0x2400)):
            state.put(0x1000 + offset, slot)
        for slot, value in ((0x2100, src), (0x2200, dst), (0x2300, old), (0x2400, index)):
            state.put(slot, value)
        state.put((src + index) & MASK, 0xA5, 1)
        return state

    def test_original_pins_imports_and_selectors(self):
        artifact = build(self.sample)
        self.assertEqual(len(artifact["windows"]), 9)
        self.assertFalse(artifact["full_callback_cfg_proven"])
        self.assertFalse(artifact["external_call_effects_proven"])
        self.assertEqual(artifact["endpoint_attributed_live_responses_added"], 0)

    def test_count_arithmetic_boundaries_and_seeded_random(self):
        rng = random.Random(239)
        pairs = [(0, 0), (0, MASK), (1, MASK), (MASK, MASK), (1 << 63, 2)]
        pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(300)]
        for a, b in pairs:
            with self.subTest(a=a, b=b):
                state = self.execute(0x1003A9CC0, self.count_state(a, b))
                product = (a * b) & MASK
                self.assertEqual(state.get(0x2400), product)
                self.assertEqual(state.get(0x1024, 4), int(product == 0))
        # Neither argument is zero in this overflow-to-zero case.
        self.assertEqual(self.execute(0x1003A9CC0, self.count_state(1 << 63, 2)).get(0x1024, 4), 1)

    def test_count_alias_counterexample(self):
        state = self.count_state(3, 7)
        state.regs["x12"] = state.regs["x11"]
        self.execute(0x1003A9CC0, state)
        self.assertEqual(state.get(0x2400), 49)
        self.assertNotEqual(state.get(0x2400), 21)

    def test_copy_both_blocks_offsets_wrap_and_byte_width(self):
        for va in (0x1003A9550, 0x1003A9F6C):
            for index, old, src, dst in ((0, 0, 0x5000, 0x6000), (7, 19, 0x5100, 0x6800),
                                         (1, 4, MASK, MASK - 2)):
                with self.subTest(va=hex(va), index=index):
                    state = self.copy_state(index, old, src, dst)
                    address = (dst + old + index) & MASK
                    state.put((address + 1) & MASK, 0xEE, 1)
                    self.execute(va, state)
                    self.assertEqual(state.get(address, 1), 0xA5)
                    self.assertEqual(state.get((address + 1) & MASK, 1), 0xEE)
                    self.assertEqual(state.events[-1]["size"], 1)

    def test_copy_index_read_epochs_not_conflated(self):
        for va, split in ((0x1003A9550, 10 * 4), (0x1003A9F6C, 6 * 4)):
            state = self.copy_state(index=2)
            self.execute(va, state, end=split)
            # Deliberate counterexample between reads, not evidence of actual interference.
            state.put(0x2400, 5)
            self.execute(va, state, start=split)
            self.assertEqual(state.get(0x6000 + 9 + 5, 1), 0xA5)
            reads = [e["value"] for e in state.events if e["kind"] == "read" and e["address"] == 0x2400]
            self.assertEqual(reads, [2, 5])

    def test_byte_store_aliases_index_slot(self):
        state = self.copy_state(index=2, old=0, dst=0x23FE)
        self.execute(0x1003A9550, state)
        self.assertEqual(state.get(0x2400), 0xA5)
        self.assertEqual(state.events[-1]["address"], 0x2400)

    def test_pointer_setup_order_with_alias(self):
        state = self.copy_state()
        state.put(0x1088, 0x9999)
        # Destination-slot write precedes the source-slot read.
        state.put(0x1090, 0x2500)
        state.put(0x1098, 0x2500)
        state.put(0x2500, 0x8888)
        self.execute(0x1003A9054, state)
        self.assertEqual(state.get(0x2100), 0x9999)
        self.assertEqual(state.get(0x2400), 0)

    def test_increment_modulo64(self):
        for index in (0, 17, MASK):
            for noise in (0, MASK, 1 << 63):
                state = self.copy_state(index=index)
                state.put(0x1118, noise)
                self.execute(0x1003A909C, state)
                self.assertEqual(state.get(0x2400), (index + 1) & MASK)

    def test_resize_arguments_stop_before_external_effects(self):
        state = BytesState({"x19": 0x1000})
        for addr, value in ((0x10C8, 0x2100), (0x1070, 0x2200), (0x1030, 0x2300),
                            (0x1060, 19), (0x2100, 0x7000), (0x2200, 23),
                            (0x100BC2728, 0x8000), (0x100B942B8, 0x9000)):
            state.put(addr, value)
        with self.assertRaises(CallBarrier) as caught:
            self.execute(0x1003A9E48, state)
        self.assertEqual(caught.exception.pc, 0x1003A9E7C)
        self.assertEqual(state.reg("x0"), 0x7000)
        self.assertEqual(state.reg("x1"), 0x8000)
        self.assertEqual(state.reg("x2"), 42)
        self.assertEqual(state.reg("x8"), 0x9000)
        self.assertEqual(state.events[-1]["kind"], "read")

    def test_resize_alias_changes_product_epoch(self):
        state = BytesState({"x19": 0x1000})
        for addr, value in ((0x10C8, 0x2100), (0x1070, 0x2200), (0x1030, 0x2200),
                            (0x1060, 19), (0x2100, 0x7000), (0x2200, 23),
                            (0x100BC2728, 0x8000), (0x100B942B8, 0x9000)):
            state.put(addr, value)
        with self.assertRaises(CallBarrier):
            self.execute(0x1003A9E48, state)
        self.assertEqual(state.reg("x2"), 38)

    def test_cleanup_count_copy_before_barrier_not_lifetime_proof(self):
        state = BytesState({"x19": 0x1000})
        for addr, value in ((0x10C8, 0x2100), (0x1078, 0x2200), (0x1070, 0x2300), (0x2300, 65)):
            state.put(addr, value)
        with self.assertRaises(CallBarrier) as caught:
            self.execute(0x1003AA080, state)
        self.assertEqual(caught.exception.pc, 0x1003AA098)
        self.assertEqual(state.get(0x2200), 65)
        self.assertEqual(state.reg("x0"), 0x2100)
        self.assertEqual(state.reg("x1"), 0)
        self.assertNotIn(0x2100, state.memory)  # No invented storeStrong effect.

    def test_unwind_is_barrier_not_length_fallthrough(self):
        state = BytesState({"x19": 0x1000})
        state.put(0x1068, 0x7000)
        with self.assertRaises(CallBarrier) as caught:
            self.execute(0x1003A9200, state)
        self.assertEqual(caught.exception.pc, 0x1003A9204)
        self.assertEqual(len(state.events), 1)

    def test_length_and_mutable_bytes_stop_before_message_send(self):
        for va, start, first, second, pc in ((0x1003A9200, 8, 0x10E0, 0x10D8, 0x1003A9218),
                                            (0x1003A94FC, 0, 0x1048, 0x1040, 0x1003A950C)):
            state = BytesState({"x19": 0x1000})
            for addr, value in ((first, 0x8000), (second, 0x7000), (0x100B942B8, 0x9000)):
                state.put(addr, value)
            with self.assertRaises(CallBarrier) as caught:
                self.execute(va, state, start=start)
            self.assertEqual(caught.exception.pc, pc)
            self.assertEqual(state.reg("x0"), 0x7000)
            self.assertEqual(state.reg("x1"), 0x8000)
            self.assertFalse(any(e["kind"] == "write" for e in state.events))

    def test_register_width_and_partial_memory_write(self):
        state = BytesState({"x8": MASK})
        state.setreg("w8", 0x1000000A5)
        self.assertEqual(state.reg("x8"), 0xA5)
        state.put(MASK - 3, 0x1122334455667788)
        state.put(0, 0xEE, 1)
        self.assertEqual(state.get(MASK - 3), 0x112233EE55667788)

    def test_missing_memory_unknown_opcode_and_truncated_fail(self):
        with self.assertRaises(KeyError):
            self.execute(0x1003A9550, BytesState({"x19": 0x1000}))
        for raw in (bytes.fromhex("c0035fd6"), bytes.fromhex("00000000"), b"\0"):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                run(self.sample, 0x1000, raw, BytesState())

    def test_pin_mutation_rejected(self):
        va = next(iter(PINS))
        with patch.dict(PINS, {va: "00" + PINS[va][2:]}), self.assertRaises(ValueError):
            build(self.sample)

    def test_selector_mutation_rejected(self):
        with patch.object(self.sample, "selector", return_value="wrong"), self.assertRaises(ValueError):
            build(self.sample)

    def test_import_mutation_rejected(self):
        original = import_slot
        def changed(sample, va):
            item = original(sample, va)
            item["name"] = "wrong"
            return item
        with patch("receive_slices.import_slot", side_effect=changed), self.assertRaises(ValueError):
            build(self.sample)
        with self.assertRaises(ValueError):
            import_slot(self.sample, 0x100B942B9)

    def test_artifact_rebuild_when_present(self):
        path = Path(__file__).resolve().parents[1] / "report/receive-bytes.json"
        if not path.exists():
            self.skipTest("artifact not generated yet")
        self.assertEqual(json.loads(path.read_text()), build(self.sample))


if __name__ == "__main__":
    unittest.main(verbosity=2)
