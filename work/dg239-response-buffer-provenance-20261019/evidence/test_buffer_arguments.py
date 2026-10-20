import unittest
from unittest.mock import patch

from buffer_arguments import BytesState, CallBarrier, PINS, Sample, build, run


class ArgumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def state(self, memory):
        result = BytesState({'x19': 0x10000})
        for address, value in memory.items():
            result.put(address, value)
        return result

    def barrier(self, address, state, pc):
        with self.assertRaises(CallBarrier) as caught:
            run(self.sample, address, bytes.fromhex(PINS[address]), state)
        self.assertEqual(caught.exception.pc, pc)
        return state

    def test_original_pins_and_selectors(self):
        result = build(self.sample)
        self.assertEqual(len(result['windows']), 10)
        self.assertFalse(result['external_effects_proven'])

    def test_class_load_is_current_memory_not_zero_file_pointer(self):
        for klass in (0x20000, 0x30000):
            state = self.state({0x100BC28F8: klass})
            run(self.sample, 0x10083CC48, bytes.fromhex(PINS[0x10083CC48]), state)
            self.assertEqual(state.get(0x109F0), klass)
            self.barrier(0x100842618, state, 0x10084261C)
            self.assertEqual(state.reg('x0'), klass)
            self.assertNotIn(0x106F8, state.memory)

    def test_init_stops_before_wrapper_not_success_substitute(self):
        state = self.state({0x10DD0: 0x20000, 0x106F8: 0x30000})
        self.barrier(0x100841FEC, state, 0x100841FF4)
        self.assertEqual((state.reg('x0'), state.reg('x1')), (0x30000, 0x20000))
        self.assertNotIn(0x11158, state.memory)

    def test_bytes_reload_is_after_external_ownership_call(self):
        state = self.state({0x11160: 0x20000, 0x20000: 0x30000})
        self.barrier(0x10083E5C8, state, 0x10083E5D4)
        self.assertEqual(state.get(0x10880), 0x30000)
        # Independent post-call preconditions, not simulated ownership effects.
        for receiver in (0x30000, 0x30001):
            post = self.state({0x10880: receiver, 0x100BC1480: 0x40000,
                               0x100B942B8: 0x50000})
            with self.assertRaises(CallBarrier) as caught:
                run(self.sample, 0x10083E5D8, bytes.fromhex(PINS[0x10083E5C8])[16:], post)
            self.assertEqual(caught.exception.pc, 0x10083E5EC)
            self.assertEqual(post.reg('x0'), receiver)
            self.assertNotIn(0x10888, post.memory)

    def test_utf8_data_and_dispatch_read_current_epoch(self):
        for obj, target in ((0x30000, 0x50000), (0x30001, 0x50001)):
            state = self.state({0x10FD8: target, 0x10B58: 0x60000,
                                0x11160: 0x20000, 0x20000: obj,
                                0x100BC1670: 0x40000})
            self.barrier(0x1008544F8, state, 0x100854514)
            self.assertEqual([state.reg(f'x{i}') for i in range(4)],
                             [0x60000, 0x40000, obj, 4])
            self.assertEqual(state.reg('x8'), target)
            self.assertNotIn(0x10B50, state.memory)

    def test_mutated_code_selector_and_import_rejected(self):
        address = 0x10083CC48
        with patch.dict(PINS, {address: '00' + PINS[address][2:]}):
            with self.assertRaisesRegex(ValueError, 'changed code'):
                build(self.sample)
        with patch.object(self.sample, 'selector', return_value='wrong'):
            with self.assertRaisesRegex(ValueError, 'changed selector'):
                build(self.sample)
        with patch.object(self.sample, 'stub_symbol', return_value={'name': 'wrong'}):
            with self.assertRaisesRegex(ValueError, 'unexpected allocation'):
                build(self.sample)


if __name__ == '__main__':
    unittest.main()
