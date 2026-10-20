# Case Scope

## meta
- case_id: dg239-protocol-takeover-20261018
- created: 2026-10-18T20:33:00-07:00
- operator: local
- project_root: /Users/tougee/Downloads/DG 管理器
- primary_skill: protocol-reverse/SKILL.md
- primary_id: R21
- lead_role: lead
- specialist_roles: []
- hint: protocol reverse offline existing logs HTTP request response decode provenance
- preset: offline-sample

## auth
- status: granted
- basis: own_system
- evidence_of_auth: User explicitly authorized offline local DG239 compatibility analysis and file writes; no network or target execution
- MUST NOT proceed if status != granted

## in_scope
- assets:
  - /Users/tougee/Downloads/DG 管理器/work/dgassistant-237-239-diff/2.3.9/DGAssistant
- surfaces: []
- activities: []

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: offline
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.
    Presets: offline-sample | ctf-public | own-system

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope.assets non-empty OR offline sample path set
  - [x] network_profile.mode chosen
  - [ ] out_of_scope reviewed
  - [ ] roles assigned (see skills/ops/role-map.md)

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
- skills/ops/IDENTITY.md
