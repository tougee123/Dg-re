"""Offline metadata ledger. No target execution, plaintext export, or input writes."""
import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(value):
    raw = value.encode() if isinstance(value, str) else json.dumps(value, sort_keys=True).encode()
    out = {"description_bytes": len(raw), "description_sha256": digest(raw)}
    # ObjC description syntax is not JSON and cannot establish NSNumber/NSString.
    if isinstance(value, str):
        try:
            obj = json.loads(value)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and "code" in obj:
            code = obj["code"]
            out["code_type"] = type(code).__name__
            out["code_is_257"] = type(code) is int and code == 257
            out["code_is_string_257"] = type(code) is str and code == "257"
    return out


def unwrap(record):
    """Return one event, never search serialized siblings for provenance."""
    if not isinstance(record, dict):
        return None, "non-object-record"
    value = record
    if isinstance(record.get("event"), dict):
        envelope = record["event"]
        if "payload" not in envelope:
            return None, "non-payload-envelope"
        value = envelope["payload"]
    elif isinstance(record.get("event"), str) and "payload" in record:
        value = record["payload"]
    elif isinstance(record.get("event"), str) and record["event"].startswith("["):
        value = record["event"]
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            match = re.fullmatch(r"\[([A-Za-z0-9_-]+)\] ([\s\S]*)", value)
            if match:
                return {"event": match[1], "value": match[2]}, "legacy-text-no-call-identity"
            return None, "unsupported-text-payload"
    if isinstance(value, dict) and isinstance(value.get("event"), str):
        return value, "typed-event"
    return None, "unsupported-payload"


def parse_jsonl(raw):
    events, counts, errors = [], collections.Counter(), []
    for line, text in enumerate(raw.splitlines(), 1):
        if not text.strip():
            counts["blank"] += 1
            continue
        try:
            obj = json.loads(text)
        except (ValueError, UnicodeError):
            errors.append({"line": line, "reason": "invalid-json"})
            counts["invalid-json"] += 1
            continue
        event, status = unwrap(obj)
        counts[status] += 1
        if event is not None:
            events.append((line, event, status))
    return events, dict(counts), errors


def analyze_calls(events):
    calls, stacks, errors = {}, collections.defaultdict(list), []
    for line, e, _ in events:
        kind, tid = e["event"], e.get("tid")
        if kind == "call-enter":
            cid = e.get("id")
            if cid in calls:
                errors.append({"line": line, "reason": "duplicate-call-id"})
                continue
            expected = stacks[tid][-1] if stacks[tid] else None
            if expected != e.get("parent"):
                errors.append({"line": line, "reason": "parent-stack-mismatch"})
            calls[cid] = {"enter_line": line, "entry": e, "events": []}
            stacks[tid].append(cid)
        elif kind == "call-return":
            cid = e.get("id")
            if cid not in calls or calls[cid]["entry"].get("tid") != tid:
                errors.append({"line": line, "reason": "unmatched-return"})
                continue
            if stacks[tid] and stacks[tid][-1] == cid:
                stacks[tid].pop()
            else:
                errors.append({"line": line, "reason": "return-stack-mismatch"})
            if "return_line" in calls[cid]:
                errors.append({"line": line, "reason": "duplicate-return"})
            calls[cid].update(return_line=line, result=e.get("result"))
        elif e.get("call") is not None:
            cid = e["call"]
            if not stacks[tid] or stacks[tid][-1] != cid:
                errors.append({"line": line, "reason": "event-active-call-mismatch"})
            if cid in calls:
                calls[cid]["events"].append(kind)
    incomplete = [cid for cid, c in calls.items() if "return_line" not in c]
    return calls, errors, incomplete


def module_base(events, calls):
    verified = any(e.get("event") == "sample-anchor-verified" and
                   e.get("offset") == "0x24b014" and
                   e.get("bytes") == "fc6fbaa9fa6701a9f85f02a9f65703a9"
                   for _, e, _ in events)
    bases = set()
    if verified:
        for _, e, _ in events:
            if e["event"] == "24B014-enter" and e.get("call") in calls:
                target = calls[e["call"]]["entry"].get("target")
                if isinstance(target, str):
                    try:
                        bases.add(int(target, 16) - 0x24B014)
                    except ValueError:
                        pass
    return next(iter(bases)) if len(bases) == 1 else None


def jsonl_ledger(raw):
    events, coverage, parse_errors = parse_jsonl(raw)
    calls, call_errors, incomplete = analyze_calls(events)
    base = module_base(events, calls)
    rows = []
    for line, e, parser in events:
        kind = e["event"]
        if kind not in {"JSON-resp", "AESdec", "FILE-read-return", "BODY", "URL", "CONNECT"}:
            continue
        row = {"line": line, "event": kind, "parser": parser,
               "tid": e.get("tid"), "call": e.get("call"),
               "origin": "unproven", **metadata(e.get("value"))}
        if kind == "JSON-resp":
            row["meaning"] = "NSJSONSerialization output description, not a socket receive"
        elif kind == "BODY":
            row["meaning"] = "setHTTPBody description, not wire bytes or send length"
        c = calls.get(e.get("call"))
        if c:
            en = c["entry"]
            row.update(enter_line=c["enter_line"], return_line=c.get("return_line"),
                       caller=en.get("caller"), observed_parent=en.get("parent"),
                       input_registers=en.get("registers"), result=c.get("result"))
            if base is not None and en.get("caller"):
                caller = int(en["caller"], 16)
                if base <= caller < base + 0x2000000:
                    row["unslid_caller"] = hex(caller - base + 0x100000000)
        rows.append(row)
    # Pointer equality is recorded as a candidate edge, never a lifetime/data-flow proof.
    edges = []
    for row in rows:
        if row["event"] != "JSON-resp" or len(row.get("input_registers") or []) < 3:
            continue
        data = row["input_registers"][2]
        if data == "0x0":
            continue
        for prior in rows:
            if prior["event"] not in {"AESdec", "FILE-read-return"}:
                continue
            returned = prior.get("return_line")
            if (prior.get("result") == data and isinstance(returned, int) and
                    returned < row["enter_line"]):
                edges.append({"producer_call": prior["call"], "consumer_call": row["call"],
                              "producer_line": prior["line"], "consumer_line": row["line"],
                              "same_tid": prior["tid"] == row["tid"],
                              "basis": "observed pointer equality only; allocation epoch unobserved"})
    return {"coverage": coverage, "parse_errors": parse_errors, "call_errors": call_errors,
            "incomplete_calls": incomplete, "calls": len(calls),
            "module_base": hex(base) if base is not None else None,
            "event_counts": dict(collections.Counter(e["event"] for _, e, _ in events)),
            "ledger": rows, "candidate_pointer_edges": edges}


def socket_records(obj, path=""):
    if isinstance(obj, dict):
        if isinstance(obj.get("socket_effects"), list):
            for i, effect in enumerate(obj["socket_effects"]):
                if isinstance(effect, dict) and effect.get("name") in {"_send", "_recv", "_connect", "_close"}:
                    yield path + "/socket_effects/" + str(i), effect
        for key, value in obj.items():
            if key != "socket_effects":
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                yield from socket_records(value, path + "/" + escaped)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from socket_records(value, path + "/" + str(i))


def socket_ledger(doc):
    rows = []
    for pointer, e in socket_records(doc):
        row = {"pointer": pointer, "event": e["name"], "fd": e.get("fd"),
               "origin": "fixture-socket-effect; live provenance not established"}
        if "raw" in e:
            try:
                raw = bytes.fromhex(e["raw"])
            except (ValueError, TypeError):
                row["error"] = "invalid-hex"
                rows.append(row)
                continue
            row.update(bytes=len(raw), sha256=digest(raw))
            if e["name"] == "_recv":
                m = re.match(rb"HTTP/1\.[01] ([0-9]{3})(?: |\r\n)", raw)
                row["http_status"] = int(m[1]) if m else None
                row["meaning"] = "EOF/no bytes" if not raw else "unattributed receive chunk"
            if e["name"] == "_send":
                m = re.match(rb"POST /index.php/api/User/(logind[01]|recharged) HTTP/1\.[01]\r\n", raw)
                if m:
                    head, sep, body = raw.partition(b"\r\n\r\n")
                    length = re.search(rb"\r\nContent-Length: ([0-9]+)", head, re.I)
                    row.update(endpoint=m[1].decode(), inline_body_bytes=len(body) if sep else None,
                               declared_body_bytes=int(length[1]) if length else None)
        rows.append(row)
    return rows


def run(root, output):
    work = root / "work"
    paths = sorted(p for p in work.rglob("*") if p.is_file() and
                   ((p.suffix in {".jsonl", ".log"} and
                     re.search(r"(raw-events|capture|event|observe)", p.name)) or
                    (p.name.endswith(".json.gz") and p.parent.name == "evidence" and
                     p.parent.parent.name.startswith("dgassistant-239-"))))
    sources = []
    for p in paths:
        raw = p.read_bytes()
        source = {"path": str(p.relative_to(root)), "sha256": digest(raw)}
        if p.name.endswith(".json.gz"):
            try:
                source.update(format="gzip-json", ledger=socket_ledger(json.loads(gzip.decompress(raw))))
            except (ValueError, OSError, UnicodeError):
                source.update(format="gzip-json", error="decode-failed")
        else:
            source.update(format="jsonl", **jsonl_ledger(raw))
        sources.append(source)
    result = {"schema": 1, "limits": ["No chronological network attribution", "No cross-file pointer joining",
              "No pointer equality promoted to same-state proof", "No fixture receives promoted to live responses"],
              "sources": sources}
    output.mkdir(parents=True, exist_ok=True)
    (output / "event-ledger.json").write_text(json.dumps(result, indent=2) + "\n")
    summary = {"sources": len(sources), "ledger_rows": sum(len(s.get("ledger", [])) for s in sources),
               "call_errors": sum(len(s.get("call_errors", [])) for s in sources),
               "parse_errors": sum(len(s.get("parse_errors", [])) for s in sources),
               "live_final_response_attribution": "not established by this metadata ledger"}
    (output / "ledger-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.root.resolve(), args.output.resolve())
