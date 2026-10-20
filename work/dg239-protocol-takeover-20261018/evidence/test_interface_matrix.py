import copy
import json
import unittest

import interface_matrix as m


def fixture(endpoint="logind0", value=None, header_only=False):
    value = {"code": "257", "data": "00"} if value is None else value
    body = json.dumps(value, separators=(",", ":")).encode()
    request = (f"POST /index.php/api/User/{endpoint} HTTP/1.1\r\n"
               "Host: offline.invalid\r\nContent-Length: 3\r\n\r\n").encode()
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    return {"socket_effects": [{"name": "_connect", "fd": 123, "raw": ""},
                               {"name": "_send", "fd": 123,
                                "raw": (request + (b"" if header_only else b"a=b")).hex()},
                               {"name": "_recv", "fd": 123, "raw": response.hex()}],
            "events": [{"name": "NATIVE:_CCCrypt", "pc": "0x100000000"},
                       {"name": "NATIVE:JSON-decode", "pc": "0x1008496ac",
                        "args": [body.hex(), 1], "result": {"error": 0, "value": value}},
                       {"name": "MODEL:append", "pc": "0x100000004"}]}


class InterfaceMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = m.build()

    def audit(self, doc):
        return m.analyze_response(doc, "logind0", "0x1008496ac")

    def test_fixture_coverage_is_not_live_coverage(self):
        rows = self.report["response_fixtures"]
        self.assertEqual(len(rows), 8)
        self.assertEqual({r["transport"]["request"]["endpoint"] for r in rows},
                         {"logind1", "logind0", "recharged"})
        for row in rows:
            self.assertFalse(row["live_transaction"])
            self.assertFalse(row["full_response_decode_proven"])
            self.assertTrue(row["parser"]["fixture_receive_bytes_equal"])
            self.assertFalse(row["transport"]["request"]["connection_epoch_verified"])

    def test_logind0_has_header_send_and_separate_constructed_body(self):
        row = self.report["construction_fixtures"][0]
        request = row["transport"]["request"]
        self.assertEqual(request["header_bytes"], 174)
        self.assertEqual(request["observed_body"]["bytes"], 0)
        self.assertEqual(request["declared_body_bytes"], 2456)
        self.assertFalse(request["complete_body_observed"])
        self.assertFalse(request["send_result_verified"])
        self.assertEqual(row["body_object_fragments"][-1]["bytes"], 2456)
        self.assertFalse(row["body_object_is_socket_send"])

    def test_second_fixture_crypto_precedes_response_parser(self):
        row = next(r for r in self.report["response_fixtures"]
                   if r["transport"]["request"]["endpoint"] == "logind0")
        self.assertEqual(len(row["crypto_calls"]), 4)
        self.assertTrue(all(c["phase"] == "before_response_parser" for c in row["crypto_calls"]))
        self.assertGreater(len(row["model_events_after_parser"]), 0)

    def test_header_only_and_split_body_are_distinguished(self):
        doc = fixture(header_only=True)
        request = self.audit(doc)["transport"]["request"]
        self.assertFalse(request["complete_body_observed"])
        doc["socket_effects"].insert(2, {"name": "_send", "fd": 123, "raw": b"a=b".hex()})
        request = self.audit(doc)["transport"]["request"]
        self.assertTrue(request["complete_body_observed"])
        self.assertEqual(request["observed_body"], m.digest(b"a=b"))

    def test_endpoint_and_request_identity_mutations_rejected(self):
        for mutation in ["endpoint", "duplicate", "connect_after", "send_fd", "recv_fd", "closed"]:
            with self.subTest(mutation=mutation):
                doc = fixture()
                effects = doc["socket_effects"]
                if mutation == "endpoint":
                    effects[1]["raw"] = bytes.fromhex(effects[1]["raw"]).replace(b"logind0", b"logind1").hex()
                elif mutation == "duplicate":
                    effects.insert(2, copy.deepcopy(effects[1]))
                elif mutation == "connect_after":
                    effects.insert(2, copy.deepcopy(effects[0]))
                elif mutation == "send_fd":
                    effects.insert(2, {"name": "_send", "fd": 124, "raw": ""})
                elif mutation == "recv_fd":
                    effects[2]["fd"] = 124
                else:
                    effects.insert(2, {"name": "_close", "fd": 123, "raw": ""})
                with self.assertRaises(ValueError):
                    self.audit(doc)

    def test_repeated_connect_does_not_become_verified_epoch(self):
        doc = fixture()
        doc["socket_effects"].insert(0, copy.deepcopy(doc["socket_effects"][0]))
        request = self.audit(doc)["transport"]["request"]
        self.assertEqual(request["connection_attempts_before_header"], 2)
        self.assertFalse(request["connection_epoch_verified"])

    def test_http_boundaries_lengths_and_framing_rejected(self):
        invalid = [b"POST /wrong HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n",
                   b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
                   b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxx",
                   b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                   b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                   b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx"]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.parse_http(raw, response=True)

    def test_interim_response_is_not_final_response(self):
        doc = fixture()
        doc["socket_effects"][2]["raw"] = b"HTTP/1.1 100 Continue\r\n\r\n".hex()
        wire, body = m.wire(doc, "logind0")
        self.assertFalse(wire["response"]["final"])
        self.assertEqual(body, b"")
        with self.assertRaisesRegex(ValueError, "no final response"):
            self.audit(doc)
        last = self.report["preflight"]["cases"][-1]["transport"]
        self.assertEqual(last["response"]["status"], 100)
        self.assertFalse(last["response"]["final"])
        self.assertTrue(last["request"]["complete_body_observed"])
        self.assertFalse(self.report["preflight"]["omission_proven"])

    def test_parser_boundary_input_options_result_and_types_rejected(self):
        for mutation in ["missing", "duplicate", "input", "options", "error", "error_bool", "result", "bool"]:
            with self.subTest(mutation=mutation):
                doc = fixture(value={"code": 257, "data": 1})
                event = doc["events"][1]
                if mutation == "missing":
                    event["pc"] = "0x100000000"
                elif mutation == "duplicate":
                    doc["events"].append(copy.deepcopy(event))
                elif mutation == "input":
                    event["args"][0] += "20"
                elif mutation == "options":
                    event["args"][1] = 0
                elif mutation == "error":
                    event["result"]["error"] = 1
                elif mutation == "error_bool":
                    event["result"]["error"] = False
                elif mutation == "result":
                    event["result"]["value"]["code"] = "257"
                else:
                    event["result"]["value"]["data"] = True
                with self.assertRaises(ValueError):
                    self.audit(doc)

    def test_recorded_numeric_and_string_codes_remain_distinct(self):
        rows = self.report["response_fixtures"][:2]
        self.assertEqual([r["parser"]["field_types"]["code"] for r in rows], ["str", "int"])

    def test_model_and_preparser_crypto_are_not_decode_proof(self):
        row = self.audit(fixture())
        self.assertEqual(row["crypto_calls"][0]["phase"], "before_response_parser")
        self.assertEqual(len(row["model_events_after_parser"]), 1)
        self.assertFalse(row["full_response_decode_proven"])

    def test_source_pin_rejects_wrong_hash(self):
        filename, (_, _, _) = next(iter(m.PINS.items()))
        with self.assertRaisesRegex(ValueError, "source SHA mismatch"):
            m.load_pinned(m.RESPONSE + filename, "0" * 64)

    def test_constructed_body_rejects_mutated_suffix_or_summary(self):
        path, sha = next(iter(m.CONSTRUCTION_PINS.items()))
        doc = m.load_pinned(path, sha)
        m.constructed_fragments(doc)
        for mutation in ["suffix", "hash", "length", "prefix"]:
            altered = copy.deepcopy(doc)
            events = altered["events"]
            if mutation == "suffix":
                events[19380]["args"][1] += " "
            elif mutation == "hash":
                events[19384]["args"][0]["sha256"] = "0" * 64
            elif mutation == "length":
                events[19384]["args"][0]["text_length"] += 1
            else:
                events[19371]["args"][1] += " "
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.constructed_fragments(altered)


if __name__ == "__main__":
    unittest.main()
