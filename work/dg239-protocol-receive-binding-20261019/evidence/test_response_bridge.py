"""Counterexamples to conflating registration, invocation and parser epochs."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from receive_slices import BytesState, CallBarrier, Sample, run
from response_bridge import PINS, build


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def execute(self, va, state, end=None):
        return run(self.sample, va, bytes.fromhex(PINS[va])[:end], state)

    def state(self, registers, memory):
        state = BytesState(registers)
        for address, value in memory.items():
            state.put(address, value)
        return state

    def barrier(self, va, state, pc):
        with self.assertRaises(CallBarrier) as caught:
            self.execute(va, state)
        self.assertEqual(caught.exception.pc, pc)
        return state

    def test_pins_and_scope(self):
        result = build(self.sample)
        self.assertEqual(len(result["windows"]), 14)
        self.assertEqual(result["retain_import"]["name"], "_objc_retain")
        self.assertEqual(self.sample.stub_symbol(0x100AE01B0)["name"], "_objc_retainAutorelease")
        for key in ("full_callback_cfg_proven", "external_call_effects_proven",
                    "baidu_omission_proven", "data3_empty_return_proven"):
            self.assertFalse(result[key])
        self.assertEqual(result["full_decoders_closed"], 0)

    def test_userdata_saved_before_retain_barrier(self):
        state = self.state({"x19": 0x1000}, {0x10B8: 0x2000, 0x2000: 0x7000,
                                                     0x100B942C8: 0x9000})
        self.barrier(0x1003A99EC, state, 0x1003A9A00)
        self.assertEqual(state.reg("x0"), 0x7000)
        self.assertEqual(state.get(0x1018), 0x7000)
        self.assertEqual(state.reg("x8"), 0x9000)
        self.assertEqual(len([e for e in state.events if e["kind"] == "write"]), 1)

    def test_postcall_uses_saved_memory_not_x0_return(self):
        # This is a separate explicit post-call precondition, not a retain implementation.
        state = self.state({"x19": 0x1000, "x0": 0xDEAD},
                           {0x10C8: 0x3000, 0x1018: 0x7000, 0x10E8: 0x8000})
        self.execute(0x1003A9A04, state)
        self.assertEqual(state.get(0x3000), 0x7000)
        self.assertNotEqual(state.get(0x3000), state.reg("x0"))

    def test_postcall_memory_versions_cannot_be_assumed_stable(self):
        for saved, slot in ((0x7001, 0x3000), (0x7000, 0x4000)):
            state = self.state({"x19": 0x1000},
                               {0x10C8: slot, 0x1018: saved, 0x10E8: 0})
            self.execute(0x1003A9A04, state)
            self.assertEqual(state.get(slot), saved)
            self.assertNotEqual((slot, saved), (0x3000, 0x7000))

    def test_registration_saves_then_passes_current_object(self):
        state = self.state({"x19": 0x1000, "x11": 0x2000, "x10": 0x3000,
                            "x9": 0x4000, "x8": 0xA5}, {0x2000: 0x6000, 0x3000: 0x7000})
        self.execute(0x100850BEC, state)
        self.barrier(0x100845FD4, state, 0x100845FE0)
        self.assertEqual((state.reg("x0"), state.reg("x1"), state.reg("x2")),
                         (0x6000, 10001, 0x7000))
        self.assertEqual(state.get(0x43DC, 4), 0xA5)

    def test_registration_save_can_alias_later_object_read(self):
        state = self.state({"x19": 0x1000, "x11": 0x2000, "x10": 0x14C0,
                            "x9": 0x4000, "x8": 0}, {0x2000: 0x6000, 0x14C0: 0x7000})
        self.execute(0x100850BEC, state)
        self.assertEqual(state.get(0x14C8), 0x6000)
        self.assertNotEqual(state.get(0x14C8), 0x7000)

    def test_option_userdata_write_and_cursor_advance(self):
        state = self.state({"sp": 0x1000, "x19": 0x4000}, {0x1008: 0x2000, 0x2000: 0x7000})
        self.execute(0x1008C7044, state)
        self.assertEqual(state.get(0x1008), 0x2008)
        self.assertEqual(state.get(0x4240), 0x7000)
        self.assertEqual(state.reg("x0"), 0)

    def test_cursor_alias_observes_write_before_read(self):
        state = self.state({"sp": 0x1000, "x19": 0x4000}, {0x1008: 0x1008})
        self.execute(0x1008C7044, state)
        self.assertEqual(state.get(0x4240), 0x1010)
        self.assertNotEqual(state.get(0x4240), 0x1008)

    def test_callback_option_stops_before_branch(self):
        state = self.state({"sp": 0x1000, "x19": 0x4000}, {0x1008: 0x2000, 0x2000: 0x7000})
        self.execute(0x1008C7078, state, 24)
        self.assertEqual(state.get(0x42B0), 0x7000)
        with self.assertRaisesRegex(ValueError, "unsupported instruction cbz"):
            run(self.sample, 0x1008C7090, bytes.fromhex(PINS[0x1008C7078])[24:28], state)

    def test_callback_registration_initial_object_and_handle_order(self):
        state = self.state({"x19": 0x1000},
                           {0x4818: 0x5000, 0x2160: 0x6000, 0x2158: 0x7000, 0x5000: 0x8000})
        self.execute(0x100834BE0, state, 20)
        self.assertEqual(state.get(0x6000), 0x7000)
        self.assertEqual(state.reg("x0"), 0x8000)
        # If object slot aliases the handle slot, the later handle read sees the write.
        state = self.state({"x19": 0x1000},
                           {0x4818: 0x5000, 0x2160: 0x5000, 0x2158: 0x7000, 0x5000: 0x8000})
        self.execute(0x100834BE0, state, 20)
        self.assertEqual(state.reg("x0"), 0x7000)

    def test_primary_and_secondary_userdata_are_distinct(self):
        for va, pc, context in ((0x1008C19AC, 0x1008C19BC, 0x7000),
                                (0x1008C19D4, 0x1008C19E4, 0x7100)):
            state = self.state({"x21": 0x4000, "x20": 0x5000, "x24": 19,
                                "x25": 0x9000, "x26": 0x9100},
                               {0x4240: 0x7000, 0x4250: 0x7100})
            self.barrier(va, state, pc)
            self.assertEqual([state.reg(f"x{i}") for i in range(4)], [0x5000, 1, 19, context])

    def test_callback_replacement_is_not_response_object_identity(self):
        state = self.state({"x19": 0x2000, "x22": 0x3000},
                           {0x2000: 0x4000, 0x42B0: 0x9000, 0x4240: 0x7000})
        self.barrier(0x1008C2534, state, 0x1008C2560)
        self.assertEqual((state.get(0x3008), state.get(0x3010)), (0x9000, 0x7000))
        self.assertEqual((state.get(0x42B0), state.get(0x4240)), (0x1008D4CB8, 0x2000))

    def test_restore_uses_current_saved_fields_not_registration_constants(self):
        state = self.state({"x8": 0x2000, "x28": 0x4000},
                           {0x2000: 0x3000, 0x3008: 0x9001, 0x3010: 0x7001})
        self.execute(0x1008C2120, state)
        self.assertEqual((state.get(0x42B0), state.get(0x4240)), (0x9001, 0x7001))

    def test_json_parser_stops_at_live_dispatch_and_reads_current_epoch(self):
        for va, pc, imp_slot, receiver_slot, data_slot in (
                (0x10084968C, 0x1008496AC, 0x7E8, 0x768, 0x1160),
                (0x1005D0888, 0x1005D08A8, 0x2A00, 0x29F8, 0x3768)):
            for obj in (0x7000, 0x7001):
                state = self.state({"x19": 0x1000},
                                   {0x1000 + imp_slot: 0x9000, 0x1000 + receiver_slot: 0x8000,
                                    0x1000 + data_slot: 0x2000, 0x2000: obj,
                                    0x100BC1410: 0xA000})
                self.barrier(va, state, pc)
                self.assertEqual([state.reg(f"x{i}") for i in range(5)],
                                 [0x8000, 0xA000, obj, 1, 0])
                self.assertEqual(state.reg("x8"), 0x9000)
                self.assertFalse(any(e["kind"] == "write" for e in state.events))

    def test_reject_changed_bytes_import_selector_and_route(self):
        va = 0x1003A99EC
        with patch.dict(PINS, {va: "00" + PINS[va][2:]}), self.assertRaises(ValueError):
            build(self.sample)
        with patch.object(self.sample, "selector", return_value="wrong"), self.assertRaises(ValueError):
            build(self.sample)
        with patch("response_bridge.import_slot", return_value={"name": "wrong"}), self.assertRaises(ValueError):
            build(self.sample)
        original = self.sample.read
        def changed(address, size):
            return b"\0" * 4 if address == 0x1008C9BC4 else original(address, size)
        with patch.object(self.sample, "read", side_effect=changed), self.assertRaises(ValueError):
            build(self.sample)

    def test_artifact_rebuild_when_present(self):
        path = Path(__file__).resolve().parents[1] / "report/response-bridge.json"
        if not path.exists():
            self.skipTest("artifact not yet generated")
        self.assertEqual(json.loads(path.read_text()), build(self.sample))


if __name__ == "__main__":
    unittest.main(verbosity=2)
