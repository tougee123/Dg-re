"""Metadata-only exhaustive JSONL/gzip inventory; endpoint mentions are not attribution."""
import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path

from event_ledger import jsonl_ledger, parse_jsonl, socket_ledger

ENDPOINT = re.compile(r"\b(logind0|logind1|recharged)\b")


def mentions(value, pointer=""):
    if isinstance(value, str):
        names = sorted(set(ENDPOINT.findall(value)))
        if names:
            yield {"pointer": pointer, "names": names,
                   "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
                   "meaning": "text mention only; no request/response identity"}
    elif isinstance(value, dict):
        for key, item in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from mentions(item, pointer + "/" + escaped)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from mentions(item, pointer + "/" + str(index))


def analyze(path, root):
    raw = path.read_bytes()
    source = {"path": str(path.relative_to(root)), "file_bytes": len(raw),
              "sha256": hashlib.sha256(raw).hexdigest()}
    if path.suffix == ".jsonl":
        result = jsonl_ledger(raw)
        events, _, _ = parse_jsonl(raw)
        result["endpoint_mentions"] = [dict(line=line, **row)
                                       for line, event, _ in events for row in mentions(event)]
        source.update(format="jsonl", **result)
    else:
        try:
            decoded = gzip.decompress(raw)
        except (OSError, EOFError):
            source.update(format="gzip", error="gzip-decompression-failed")
            return source
        source["decoded_bytes"] = len(decoded)
        try:
            obj = json.loads(decoded)
        except (ValueError, UnicodeError):
            source.update(format="gzip-non-json", error="not-a-single-json-document")
            return source
        source.update(format="gzip-json", top_level_type=type(obj).__name__,
                      ledger=socket_ledger(obj), endpoint_mentions=list(mentions(obj)))
    return source


def build(root, previous):
    paths = sorted(p for p in (root / "work").rglob("*")
                   if p.is_file() and p.suffix in {".jsonl", ".gz"})
    old = {s["path"]: s["sha256"] for s in previous["sources"]}
    sources = [analyze(p, root) for p in paths]
    counts = collections.Counter(s["format"] for s in sources)
    for source in sources:
        source["previous_inventory"] = ("same-hash" if old.get(source["path"]) == source["sha256"]
                                        else "changed" if source["path"] in old else "not-in-prior-ledger")
    return {"schema": 1,
            "coverage": "all files ending .jsonl or .gz recursively under work at scan time; not all formats",
            "limits": ["Text mentions do not bind parser events to endpoints",
                       "Modeled socket effects are not live network captures",
                       "No chronology-only or cross-file pointer attribution",
                       "Unsupported record schemas remain coverage gaps"],
            "summary": {"files": len(sources), "formats": dict(counts),
                        "newly_inventoried_files": sum(s["previous_inventory"] == "not-in-prior-ledger" for s in sources),
                        "changed_files": sum(s["previous_inventory"] == "changed" for s in sources),
                        "file_bytes": sum(s["file_bytes"] for s in sources)},
            "sources": sources}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build(args.root.resolve(), json.loads(args.previous.read_text()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
