import gzip
import json
import tempfile
import unittest
from pathlib import Path

from corpus_inventory import analyze, build, mentions


class CorpusInventoryTests(unittest.TestCase):
    def test_endpoint_text_is_only_a_mention_and_not_exported(self):
        value = {"a/b~c": ["local secret logind0 then recharged"]}
        rows = list(mentions(value))
        self.assertEqual(rows[0]["pointer"], "/a~1b~0c/0")
        self.assertEqual(rows[0]["names"], ["logind0", "recharged"])
        self.assertNotIn("secret", json.dumps(rows))
        self.assertIn("no request/response identity", rows[0]["meaning"])

    def test_bad_gzip_and_non_json_remain_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.gz"
            path.write_bytes(b"not gzip")
            self.assertEqual(analyze(path, root)["error"], "gzip-decompression-failed")
            path.write_bytes(gzip.compress(b"not json"))
            self.assertEqual(analyze(path, root)["error"], "not-a-single-json-document")

    def test_inventory_includes_nonstandard_filenames_and_hash_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            path = work / "previously-overlooked.jsonl"
            path.write_text('{"event":"URL","value":"logind0"}\n')
            first = build(root, {"sources": []})
            self.assertEqual(first["summary"]["newly_inventoried_files"], 1)
            self.assertEqual(first["sources"][0]["endpoint_mentions"][0]["line"], 1)
            self.assertEqual(build(root, first)["summary"]["changed_files"], 0)
            path.write_text('{"event":"URL","value":"logind1"}\n')
            self.assertEqual(build(root, first)["summary"]["changed_files"], 1)


if __name__ == "__main__":
    unittest.main()
