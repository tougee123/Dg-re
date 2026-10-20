# Timeline (append-only)

## 2026-10-18T20:33:00-07:00 | lead | init
- action: case-init
- command_or_ref: skills/scripts/case-init.sh
- result_summary: case directory created; scope ready_for_act=true
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- decision_delta: [case_initialized]
- carry_forward_refs: [scope.md]
- next: open PRIMARY SKILL.md and ACT within scope

## 2026-10-19 | lead | offline-review-and-limited-publication
- action: independently rebuild evidence indexes, validate byte derivations and publish bounded corrections
- command_or_ref: python3 -m unittest discover -s work/dg239-protocol-takeover-20261018/evidence -p 'test_*.py'
- result_summary: two runs of 50 tests passed (47.848 / 47.520 seconds); no target execution, device connection, redemption or authorization modification
- artifacts: [report/PROTOCOL_REVIEW.md, report/interface-matrix.json, report/parser-stages.json, report/data3-branches.json, report/callback-gate.json, publication/publication-record.json]
- evidence_ids: [interface-fixtures, request-construction, parser-stages, data3-local-bytes, callback-epochs]
- decision_delta: [logind0-construction-not-send, recharged-153-plus-374, fixtures-not-live-responses, data3-short-arm-not-empty-input-return, baidu-omission-unproven]
- carry_forward_refs: [scope.md, report/PROTOCOL_REVIEW.md]
- publication_check: independently re-read three shared documents and backups; before/after SHA, byte counts, prefix preservation and unified diff content all matched; local report links resolved
- next: keep live response ownership, generic transforms, complete response validation and cache-to-UI same-attempt proof open; do not treat limited publication as compatible SDK acceptance
