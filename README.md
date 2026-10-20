# DG 2.3.9 / Dot offline handoff

Start with [DOT_HANDOFF.md](DOT_HANDOFF.md). This private research repository contains original evidence, a pinned binary sample, analysis scripts, negative tests, and historical reports. It is **not a completed compatible activation SDK**.

## Reproduce

Python 3.11+ recommended. In a virtual environment:

```sh
python3 -m pip install -r requirements.txt
python3 handoff/verify_export.py
```

Verification is offline. It hashes every exported file, runs three unittest suites, and reruns five result-generating scripts in a temporary copy. It never connects to a device or starts DG. Allow several minutes and at least 1 GB free temporary disk space.

- `DOT_HANDOFF.md`: evidence hierarchy, limitations and next steps.
- `handoff/TEST_RESULTS.txt`: packaging-time verification results.
- `EXPORT_INVENTORY.json`: exact shipped file sizes and SHA256.
- `work/dg239-protocol-takeover-20261018/`: interface matrix, ledger, corpus inventory, reconstruction and mutation tests.
- `work/dg239-protocol-receive-binding-20261019/`: transitive receive/parse analysis dependencies.
- `work/dg239-response-buffer-provenance-20261019/`: buffer provenance analysis.
- `work/dg239-gap-reconciliation-20261019/` and `work/dg239-logind0-receive-parser-bridge-20261019/`: later gap analysis (claims require the caveats in handoff).
- Other `work/` paths: original source records referenced by the inventories, not complete historical case directories.
- `work/dgassistant-237-239-diff/2.3.9/DGAssistant`: SHA-pinned analysis sample, not to execute.

Raw records may contain sensitive authorization/device data. Keep this repository private; do not paste raw payloads into chats, issues or CI logs. No workflow or automatic capture is installed.
