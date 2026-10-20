import json
import unittest
from event_ledger import jsonl_ledger, metadata, parse_jsonl, socket_ledger


class LedgerTests(unittest.TestCase):
    def test_mixed_envelopes_and_bad_line(self):
        data = [
            {"event": {"type": "send", "payload": {"event": "JSON-resp", "value": "{}"}}},
            {"event": {"type": "send", "payload": "[JSON-resp] {}"}},
            {"event": "[JSON-resp] {}"},
            {"event": {"detached": "application-requested"}},
            {"event": {"payload": "unsupported"}},
        ]
        raw = b"\n".join(json.dumps(d).encode() for d in data) + b"\n{broken\n"
        events, counts, errors = parse_jsonl(raw)
        self.assertEqual([x[0] for x in events], [1, 2, 3])
        self.assertEqual(errors, [{"line": 6, "reason": "invalid-json"}])
        self.assertEqual(sum(counts.values()), 6)

    def test_no_chronological_attribution(self):
        events = [{"event": k, "tid": 1, "value": "{}"}
                  for k in ["CONNECT", "JSON-req", "JSON-resp"]]
        result = jsonl_ledger(b"\n".join(json.dumps(e).encode() for e in events))
        self.assertTrue(all(r["origin"] == "unproven" for r in result["ledger"]))

    def test_json_code_type_is_not_description_token(self):
        self.assertTrue(metadata('{"code":257}')["code_is_257"])
        self.assertFalse(metadata('{"code":"257"}')["code_is_257"])
        self.assertTrue(metadata('{"code":"257"}')["code_is_string_257"])
        self.assertNotIn("code_type", metadata("{code = 257;}"))
        self.assertNotIn("code_type", metadata('{"text":"code = 257"}'))

    def test_sibling_marker_not_receive_origin(self):
        doc = {"note": "not a valid server response MODEL:tracked-calloc",
               "socket_effects": [{"name": "_recv", "fd": 1, "raw": ""},
                                  {"name": "_recv", "fd": 1, "raw": "deadbeef"}]}
        rows = socket_ledger(doc)
        self.assertEqual([r["bytes"] for r in rows], [0, 4])
        self.assertTrue(all("fixture-socket" in r["origin"] for r in rows))
        self.assertEqual(rows[0]["pointer"], "/socket_effects/0")

    def test_request_header_not_body_or_final_response(self):
        head = b"POST /index.php/api/User/logind0 HTTP/1.1\r\nContent-Length: 3\r\n\r\n"
        rows = socket_ledger({"socket_effects": [
            {"name": "_send", "raw": head.hex()},
            {"name": "_recv", "raw": b"HTTP/1.1 100 Continue\r\n\r\n".hex()},
            {"name": "_send", "raw": (head + b"abc").hex()}]})
        self.assertEqual(rows[0]["inline_body_bytes"], 0)
        self.assertEqual(rows[0]["declared_body_bytes"], 3)
        self.assertEqual(rows[1]["http_status"], 100)
        self.assertEqual(rows[2]["inline_body_bytes"], 3)

    def test_parent_and_event_identity_checked(self):
        events = [
            {"event": "call-enter", "id": 1, "tid": 2, "parent": None},
            {"event": "call-enter", "id": 2, "tid": 2, "parent": None},
            {"event": "JSON-resp", "tid": 2, "call": 1, "value": "{}"},
            {"event": "call-return", "id": 2, "tid": 2, "result": "0x1"},
            {"event": "call-return", "id": 1, "tid": 2, "result": "0x1"},
        ]
        result = jsonl_ledger(b"\n".join(json.dumps(e).encode() for e in events))
        self.assertEqual({e["reason"] for e in result["call_errors"]},
                         {"parent-stack-mismatch", "event-active-call-mismatch"})
        self.assertEqual(result["incomplete_calls"], [])


if __name__ == "__main__":
    unittest.main()
