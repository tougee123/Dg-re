import random
import unittest

import z3

from binary_evidence import Sample
from data3_branches import (FRAME, MASK, PINS, build, dispatcher_expression, dispatcher_model,
                            long_reference, models, predicate, short_reference, solve)


class Data3BranchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()
        cls.symbols, cls.short, cls.long = models(cls.sample)

    def test_original_windows_and_bounded_proofs(self):
        report = build(self.sample)
        self.assertEqual(report["proofs"]["short_index1_feasible"], "unsat")
        self.assertEqual(report["proofs"]["long_formula_mismatch"], "unsat")
        self.assertEqual(report["proofs"]["length_gate_mismatch"], "unsat")
        self.assertIn("not a proven return", " ".join(report["limits"]))

    def test_every_pinned_window_rejects_mutated_bytes(self):
        for address in PINS:
            with self.subTest(address=hex(address)):
                class Mutated:
                    def read(inner, va, size):
                        raw = self.sample.read(va, size)
                        return bytes([raw[0] ^ 1]) + raw[1:]
                with self.assertRaisesRegex(ValueError, "byte mismatch"):
                    predicate(Mutated(), address, {})

    def test_interpreted_predicates_against_concrete_reference(self):
        rng = random.Random(239)
        values = [(0, 0, 0, 0), (MASK, MASK, MASK, MASK)]
        values += [tuple(rng.getrandbits(32) for _ in range(4)) for _ in range(128)]
        for row in values:
            bindings = [(v, z3.BitVecVal(x, 32)) for v, x in zip(self.symbols, row)]
            self.assertEqual(z3.is_true(z3.simplify(z3.substitute(self.short, *bindings))),
                             short_reference(*row[:2]))
            self.assertEqual(z3.is_true(z3.simplify(z3.substitute(self.long, *bindings))),
                             long_reference(*row))

    def test_unsigned_threshold_and_changed_constant(self):
        a, b, p, q = self.symbols
        for result in [0, 0x27297BDE, 0x27297BDF, 0x27297BE0, 0x80000000, MASK]:
            row = [0, 0, 0, result ^ 0xEB4668DC]
            bindings = [(v, z3.BitVecVal(x, 32)) for v, x in zip(self.symbols, row)]
            self.assertEqual(z3.is_true(z3.simplify(z3.substitute(self.long, *bindings))),
                             result > 0x27297BDF)
        # Flipping bit 0 cannot cross this odd threshold; it is not a negative test.
        equivalent = z3.UGT(a ^ b ^ 0xEB4668DD ^ p ^ q, z3.BitVecVal(0x27297BDF, 32))
        self.assertEqual(solve(self.long != equivalent), "unsat")
        wrong = z3.UGT(a ^ b ^ 0xEB4669DC ^ p ^ q, z3.BitVecVal(0x27297BDF, 32))
        self.assertEqual(solve(self.long != wrong), "sat")
        signed = (a ^ b ^ 0xEB4668DC ^ p ^ q) > z3.BitVecVal(0x27297BDF, 32)
        self.assertEqual(solve(self.long != signed), "sat")

    def test_length_gate_is_unsigned_and_not_body_length(self):
        for length in [0, 1, 2, 40, 1 << 63, (1 << 64) - 1]:
            condition = predicate(self.sample, 0x1003C38D8,
                                  {FRAME + 0x520: 0x300000000, FRAME + 0x508: 0x400000000,
                                   FRAME + 0x130: length})
            self.assertEqual(z3.is_true(z3.simplify(condition)), length in {0, 1})

    def test_following_dispatcher_against_independent_uint32_reference(self):
        a, b, condition = dispatcher_model(self.sample)
        rng = random.Random(23901)
        decisions = set()
        for av, bv in [(0, 0), (MASK, 0), (0, MASK)] + [
                (rng.getrandbits(32), rng.getrandbits(32)) for _ in range(128)]:
            delta = (av - bv) & MASK
            first = ((delta & 0x55B3127C) * (0xAA4CED83 & ~delta)) & MASK
            second = ((delta | 0xAA4CED83) * (delta & 0xAA4CED83)) & MASK
            lhs = (second + first + 0x7B980AC3 - 0x6EEE7759
                   - 0x3EF50ED8 + 0x6EEE7759) & MASK
            expected = lhs >= 0x6A96D7E0
            got = z3.simplify(z3.substitute(condition, (a, z3.BitVecVal(av, 32)),
                                             (b, z3.BitVecVal(bv, 32))))
            self.assertEqual(z3.is_true(got), expected)
            decisions.add(expected)
        self.assertEqual(decisions, {False, True})

    def test_short_dispatcher_negative_vectors_and_cleanup_table(self):
        # Find concrete distinctions without repeating a nonlinear whole-formula timeout.
        rng = random.Random(23902)
        hits = {"signed": False, "constant": False, "initializer": False}
        for _ in range(1024):
            av, bv = rng.getrandbits(32), rng.getrandbits(32)
            value = dispatcher_expression(av, bv, 0xAA4CED83) & MASK
            good = value >= 0x6A96D7E0
            hits["signed"] |= good != ((value if value < 1 << 31 else value - (1 << 32)) >= 0x6A96D7E0)
            hits["constant"] |= good != ((value ^ (1 << 31)) >= 0x6A96D7E0)
            other = dispatcher_expression(av, bv, 0xAA4CED82) & MASK
            hits["initializer"] |= good != (other >= 0x6A96D7E0)
        self.assertTrue(all(hits.values()), hits)
        report = build(self.sample)
        self.assertEqual(report["short_dispatcher_proofs"],
                         {"formula_mismatch": "unsat", "index0_feasible": "sat", "index1_feasible": "sat"})
        self.assertEqual(report["cleanup_slot"]["target"], "0x1003c5e7c")


if __name__ == "__main__":
    unittest.main()
