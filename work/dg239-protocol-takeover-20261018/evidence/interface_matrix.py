"""Offline fixture provenance; output hashes/locations/types, never payload values.

NATIVE labels in interpreter logs are not live network observations. Equality of
a fixture receive body and parser argument proves only that local byte bridge.
"""
import gzip
import hashlib
import json
import re
from pathlib import Path

from binary_evidence import ROOT

RESPONSE = "work/dgassistant-239-response/evidence/"
PINS = {
    "first-negative-protocol-257-native.json.gz": ("c5cdfa6b680fa72143928120858ecfdda60da54b7311a4b9baf8b804a0e49c61", "logind1", "0x1005d08a8"),
    "first-negative-numeric-257.json.gz": ("83cd29d8da8d5a76b7e0481fe4ebef595dcd2066349e72093e069386e2353302", "logind1", "0x1005d08a8"),
    "second-negative-protocol-257-native.json.gz": ("98690f9953e78a2ce7d7eee55899313d7b4f2be5ae5f55a4e5c1eff320c34a6a", "logind0", "0x1008496ac"),
    "activation-negative-activation-257.json.gz": ("b52a63678b124bb66492aaa7c99d36b56667188f0722ed7cc8a3c0171e2b151e", "recharged", "0x10037c868"),
    "activation-negative-activation-status-303.json.gz": ("b5a6f7db19294741ae5a7399d0d6ed28f05798d9c9e38442832be744fbc18946", "recharged", "0x10037c868"),
    "activation-negative-activation-status-304.json.gz": ("60655d7f03c5da5021e2e661a143a2f4499540f2d7505d07089062cbab5ec3fd", "recharged", "0x10037c868"),
    "activation-negative-activation-status-305.json.gz": ("c0c81bd0794611b76d46923f69a734c65e1f43005caa5186373a6f0dff9e9f8e", "recharged", "0x10037c868"),
    "activation-negative-activation-status-306.json.gz": ("99fc3a1947e20d8a51c862a594005d64c3d864628417a7c117ec7b0c473485fc", "recharged", "0x10037c868"),
}
CONSTRUCTION_PINS = {
    "work/dgassistant-239-startup/evidence/activation-second-json-exploration.json.gz": "5908d5aff538cc864be31906f3d6837581db1294c2d719e017790d5ffb61a5b5",
    "work/dgassistant-239-startup/evidence/activation-clipboard-final-exploration.json.gz": "946560b2c77ae7dd7793384e6af1a4459dd6c50de298758d0690e2f2a2c33cbd",
}
PREFLIGHT_SOURCE = "work/dgassistant-239-auth/evidence/response-negative-exploration.json.gz"
PREFLIGHT_SHA = "1fb641df4bda4bddb48ba9712c9e3d775d826b5091e5714d892c58296ca05d92"
BODY_EVENTS = [(19374, 1, 2068, "59af6239da16322c74068ba12b83f832a0c29da2b5cd9dffe9987c36c229cc06"),
               (19377, 0, 2422, "7b0d3b333153a6c1ebb8261086bd13c769d473c0020ba5ede64d088d28a27ad2"),
               (19380, 0, 2439, "eadd3fb7f68d9de8457674614cd6084a3251de27a75e0857e6bc760fbe6fe048"),
               (19384, 0, 2456, "fcf2cbae9e512dde841b7df9fdfdb0641a6938e4fdb5cb4464716425bb64740c")]
CRYPTO = {"NATIVE:_CCCrypt", "NATIVE:_SecKeyEncrypt", "NATIVE:_SecKeyDecrypt"}


def digest(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def error_is_zero(result):
    return type(result.get("error")) is int and result["error"] == 0


def same_json(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def load_pinned(path, expected):
    raw = (ROOT / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("source SHA mismatch: " + path)
    return json.loads(gzip.decompress(raw))


def parse_http(raw, response=False):
    """One Content-Length-framed message. No permissive truncation/TE guessing."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise ValueError("missing HTTP header boundary")
    lines = head.split(b"\r\n")
    if response:
        match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?", lines[0])
    else:
        match = re.fullmatch(rb"POST (/index\.php/api/User/(logind1|logind0|recharged)) HTTP/1\.[01]", lines[0])
    if not match:
        raise ValueError("unexpected HTTP start line")
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b":")
        key = key.lower()
        if not colon or not key or key in headers:
            raise ValueError("malformed or duplicate header")
        headers[key] = value.strip()
    if b"transfer-encoding" in headers:
        raise ValueError("transfer encoding not supported by this bounded audit")
    length = headers.get(b"content-length")
    if length is not None and not re.fullmatch(rb"[0-9]+", length):
        raise ValueError("invalid Content-Length")
    result = {"header_bytes": len(head) + 4, "body": body,
              "declared_body_bytes": int(length) if length is not None else None,
              "header_names": [key.decode("ascii") for key in headers]}
    if response:
        result["status"] = int(match[1])
        if 100 <= result["status"] < 200:
            if body or length not in (None, b"0"):
                raise ValueError("interim response has unexpected body")
        elif length is None or len(body) != int(length):
            raise ValueError("incomplete or unframed final response")
    else:
        result["endpoint"] = match[2].decode("ascii")
        if length is None or len(body) > int(length):
            raise ValueError("unframed or oversized request body")
    return result


def wire(doc, expected_endpoint):
    effects = doc["socket_effects"]
    sends = [(i, e, bytes.fromhex(e["raw"])) for i, e in enumerate(effects)
             if e["name"] == "_send"]
    headers = [(i, e, raw) for i, e, raw in sends if raw.startswith(b"POST ")]
    if len(headers) != 1:
        raise ValueError("request identity missing or ambiguous")
    index, effect, raw = headers[0]
    request = parse_http(raw)
    if request["endpoint"] != expected_endpoint:
        raise ValueError("endpoint mismatch")
    fd = effect["fd"]
    if any(e["fd"] != fd for _, e, _ in sends):
        raise ValueError("multiple send file descriptors")
    # Repeated connect before the send is recorded, not silently removed. A
    # reconnect after the header invalidates the bounded transaction identity.
    if any(e["name"] == "_connect" for e in effects[index + 1:]):
        raise ValueError("connection epoch changed after request header")
    if any(e["name"] in {"_close", "_shutdown"} and e["fd"] == fd
           and any(later["name"] in {"_send", "_recv"} and later["fd"] == fd
                   for later in effects[i + 1:]) for i, e in enumerate(effects[index + 1:], index + 1)):
        raise ValueError("socket used after recorded close or shutdown")
    if any(i < index for i, _, _ in sends):
        raise ValueError("unassigned body before request header")
    body = request.pop("body") + b"".join(data for i, _, data in sends if i > index)
    if len(body) > request["declared_body_bytes"]:
        raise ValueError("aggregate request body exceeds declared length")
    response_bytes = b""
    response_effects = []
    for i, e in enumerate(effects):
        if e["name"] == "_recv" and i > index:
            if e["fd"] != fd:
                raise ValueError("receive FD mismatch")
            response_bytes += bytes.fromhex(e["raw"])
            response_effects.append(i)
    response = parse_http(response_bytes, response=True) if response_bytes else None
    response_body = response.pop("body") if response else None
    return {"request": {**request, "send_effect_indices": [i for i, _, _ in sends],
                        "header_effect_index": index, "fd": fd,
                        "connection_attempts_before_header": sum(e["name"] == "_connect" and e["fd"] == fd for e in effects[:index]),
                        "observed_body": digest(body),
                        "complete_body_observed": len(body) == request["declared_body_bytes"],
                        "send_result_verified": False,
                        "connection_epoch_verified": False,
                        "meaning": "Recorded interpreter send buffers, not live transmitted bytes"},
            "response": ({**response, "receive_effect_indices": response_effects,
                          "wire": digest(response_bytes), "body": digest(response_body),
                          "final": response["status"] >= 200} if response else None)}, response_body


def analyze_response(doc, endpoint, boundary_pc):
    transport, body = wire(doc, endpoint)
    candidates = [(i, e) for i, e in enumerate(doc["events"])
                  if e.get("name") == "NATIVE:JSON-decode" and e.get("pc") == boundary_pc]
    if len(candidates) != 1:
        raise ValueError("parser boundary missing or duplicated")
    boundary, event = candidates[0]
    data = bytes.fromhex(event["args"][0])
    if event["args"][1] != 1:
        raise ValueError("unexpected parser options")
    if not transport["response"] or not transport["response"]["final"]:
        raise ValueError("no final response at parser boundary")
    if data != body:
        raise ValueError("parser input differs from final fixture response body")
    parsed = json.loads(data)
    result = event["result"]
    if not error_is_zero(result) or not same_json(result.get("value"), parsed):
        raise ValueError("recorded parser result disagrees with JSON bytes")
    if not isinstance(parsed, dict):
        raise ValueError("fixture response must be a JSON dictionary")
    crypto = [{"event_index": i, "event_pointer": f"/events/{i}", "pc": e["pc"], "name": e["name"],
               "phase": "before_response_parser" if i < boundary else "after_response_parser"}
              for i, e in enumerate(doc["events"]) if e.get("name") in CRYPTO]
    later = [{"event_index": i, "pc": e["pc"], "input": digest(bytes.fromhex(e["args"][0])),
              "result_type": type(e["result"].get("value")).__name__}
             for i, e in enumerate(doc["events"]) if i > boundary and e.get("name") == "NATIVE:JSON-decode"]
    return {"evidence_class": "offline_interpreter_fixture", "live_transaction": False,
            "transport": transport,
            "parser": {"event_index": boundary, "event_pointer": f"/events/{boundary}",
                       "input_pointer": f"/events/{boundary}/args/0", "pc": boundary_pc,
                       "input": digest(data), "fixture_receive_bytes_equal": True,
                       "field_types": {key: type(value).__name__ for key, value in parsed.items()}},
            "crypto_calls": crypto, "later_json_parsers": later,
            "model_events_after_parser": [{"event_index": i, "pc": e["pc"], "name": e["name"]}
                                          for i, e in enumerate(doc["events"]) if i > boundary and e.get("name", "").startswith("MODEL:")],
            "full_response_decode_proven": False,
            "limits": ["Fixture receive bytes, not a live server response",
                       "Pre-parser crypto is not evidence of response decryption",
                       "Post-parser model operations are not native implementation proofs",
                       "No same-state authorization acceptance or UI reachability proof"]}


def construction(doc, endpoint):
    transport, _ = wire(doc, endpoint)
    encodes = []
    for i, event in enumerate(doc["events"]):
        if event.get("name") == "NATIVE:JSON-encode":
            value = event["args"][0]
            result = event["result"]
            encoded = bytes.fromhex(result["hex"])
            if not error_is_zero(result) or not same_json(json.loads(encoded), value):
                raise ValueError("JSON construction record mismatch")
            encodes.append({"event_index": i, "event_pointer": f"/events/{i}", "pc": event["pc"],
                            "fields": {key: type(v).__name__ for key, v in value.items()},
                            "encoded": digest(encoded)})
    return {"evidence_class": "offline_interpreter_fixture", "live_transaction": False,
            "transport": transport, "json_constructions": encodes}


def constructed_fragments(doc):
    events = doc["events"]
    payloads = [p for p in doc["payloads"] if p["pc"] == "0x10089669c"]
    if len(payloads) != 1:
        raise ValueError("body JSON payload identity ambiguous")
    payload = payloads[0]
    native = bytes.fromhex(payload["native_json_hex"]).decode("utf-8")
    if not same_json(json.loads(native), payload["value"]):
        raise ValueError("body JSON payload mismatch")
    prefix = events[19371]["args"][0] + events[19371]["args"][1]
    if prefix != events[19374]["args"][0]:
        raise ValueError("body prefix bridge mismatch")
    segment = "&data3=" + native
    first = prefix + segment
    second = first + events[19377]["args"][1]
    body = second + events[19380]["args"][1]
    fragments = []
    for (index, arg, length, expected), text in zip(BODY_EVENTS, [segment, first, second, body]):
        summary = events[index]["args"][arg]
        if (summary["text_length"] != len(text) or summary["sha256"] != expected
                or digest(text.encode("utf-8")) != {"bytes": length, "sha256": expected}):
            raise ValueError("constructed body fragment mismatch")
        fragments.append({"json_pointer": f"/events/{index}/args/{arg}",
                          "pc": events[index]["pc"], **digest(text.encode("utf-8"))})
    keys = [pair.split("=", 1)[0] for pair in body.split("&")]
    if keys != ["id", "data", "data2", "data3", "data5", "data6"]:
        raise ValueError("constructed body field order mismatch")
    return {"body_object_fragments": fragments, "body_fields": keys,
            "body_object_is_socket_send": False}


def build():
    responses = []
    for filename, (sha, endpoint, pc) in PINS.items():
        path = RESPONSE + filename
        responses.append({"source": path, "source_sha256": sha,
                          **analyze_response(load_pinned(path, sha), endpoint, pc)})
    constructions = []
    for path, sha in CONSTRUCTION_PINS.items():
        endpoint = "logind0" if "second-json" in path else "recharged"
        doc = load_pinned(path, sha)
        row = {"source": path, "source_sha256": sha, **construction(doc, endpoint)}
        if endpoint == "logind0":
            row.update(constructed_fragments(doc))
        constructions.append(row)
    cases = load_pinned(PREFLIGHT_SOURCE, PREFLIGHT_SHA)
    preflight = []
    for index, doc in enumerate(cases):
        if doc["socket_effects"]:
            transport, _ = wire(doc, "logind1")
        else:
            transport = None
        preflight.append({"case_pointer": f"/{index}", "transport": transport,
                          "event_count": len(doc["events"]), "evidence_class": "offline_interpreter_fixture"})
    return {"response_fixtures": responses, "construction_fixtures": constructions,
            "preflight": {"source": PREFLIGHT_SOURCE, "source_sha256": PREFLIGHT_SHA,
                          "cases": preflight, "omission_proven": False},
            "scope": "Offline metadata audit only; no target execution, requests, redemption, or authorization changes"}


def main():
    report = build()
    output = Path(__file__).resolve().parents[1] / "report/interface-matrix.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"response_fixtures": len(report["response_fixtures"]),
                      "construction_fixtures": len(report["construction_fixtures"]),
                      "live_transactions_proven": 0, "full_response_decodes_proven": 0}))


if __name__ == "__main__":
    main()
