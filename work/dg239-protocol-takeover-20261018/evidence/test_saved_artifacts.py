"""Rebuild saved metadata without overwriting historical or current evidence."""
import collections
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from binary_evidence import ROOT, Sample
import callback_bytes
import callback_gate
import data3_branches
import event_ledger
import interface_matrix
import parser_stages

REPORT = Path(__file__).resolve().parents[1] / "report"


def saved(name):
    return json.loads((REPORT / (name + ".json")).read_bytes())


class SavedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Sample()

    def test_saved_interface_matrix_matches_originals(self):
        self.assertEqual(saved("interface-matrix"), interface_matrix.build())

    def test_saved_binary_derivations_match_original(self):
        for name, module in [("callback-bytes", callback_bytes),
                             ("callback-gate", callback_gate),
                             ("data3-branches", data3_branches)]:
            with self.subTest(name=name):
                self.assertEqual(saved(name), module.build(self.sample))

    def test_saved_parser_metadata_matches_original_logs(self):
        sources = [(p, (ROOT / p).read_bytes()) for p in parser_stages.SOURCES]
        self.assertEqual(saved("parser-stages"), parser_stages.build(self.sample, sources))

    def test_inventory_original_hashes_and_totals(self):
        report = saved("corpus-inventory")
        sources = report["sources"]
        self.assertEqual(len(sources), len({s["path"] for s in sources}))
        for source in sources:
            with self.subTest(path=source["path"]):
                raw = (ROOT / source["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), source["sha256"])
                self.assertEqual(len(raw), source["file_bytes"])
        self.assertEqual(report["summary"], {
            "files": len(sources),
            "formats": dict(collections.Counter(s["format"] for s in sources)),
            "newly_inventoried_files": sum(s["previous_inventory"] == "not-in-prior-ledger"
                                           for s in sources),
            "changed_files": sum(s["previous_inventory"] == "changed" for s in sources),
            "file_bytes": sum(s["file_bytes"] for s in sources),
        })

    def test_ledger_rebuild_in_temporary_directory(self):
        with tempfile.TemporaryDirectory(prefix="dg239-ledger-audit-") as directory:
            output = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                event_ledger.run(ROOT, output)
            for name in ["event-ledger", "ledger-summary"]:
                with self.subTest(name=name):
                    self.assertEqual(saved(name), json.loads((output / (name + ".json")).read_bytes()))
        self.assertLess(saved("ledger-summary")["sources"],
                        saved("corpus-inventory")["summary"]["files"])

    def test_recharged_header_and_body_are_distinct(self):
        row = next(r for r in saved("interface-matrix")["construction_fixtures"]
                   if r["transport"]["request"]["endpoint"] == "recharged")
        request = row["transport"]["request"]
        self.assertEqual(request["header_bytes"], 153)
        self.assertEqual(request["observed_body"]["bytes"], 374)
        self.assertEqual(request["header_bytes"] + request["observed_body"]["bytes"], 527)
        self.assertFalse(request["send_result_verified"])


if __name__ == "__main__":
    unittest.main()
