---
name: prowler-compliance
description: "Trigger: When creating, syncing, auditing, or registering Prowler compliance frameworks, mappings, or output formatters. Governs the four-layer compliance architecture, upstream sync workflow, and honest check-to-requirement coverage decisions."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2"
  scope: [root, sdk]
  auto_invoke:
    - "Creating/updating compliance frameworks"
    - "Mapping checks to compliance controls"
    - "Syncing compliance framework with upstream catalog"
    - "Auditing check-to-requirement mappings as a cloud auditor"
    - "Adding a compliance output formatter (per-provider class + table dispatcher)"
    - "Fixing compliance JSON bugs (duplicate IDs, empty Section, stale refs)"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when the work touches compliance JSON catalogs, `compliance_models.py`, check mappings, output formatter registration, or UI/API surfaces that consume compliance data.

## Hard Rules

- Treat compliance as a four-layer system: SDK models → `prowler/compliance/{provider}/*.json` → CLI/API output formatters → API/UI consumers.
- `Generic_Compliance_Requirement_Attribute` MUST stay last in the `Compliance_Requirement.Attributes` union in `prowler/lib/check/compliance_models.py`.
- Never ship `Version: ""`; `get_check_compliance()` builds `{Framework}-{Version}` only when version exists, so empty version silently breaks downstream matching.
- Pre-validate every `Checks[]` entry against provider `*.metadata.json` inventories before writing framework JSON.
- Audit mappings by literal coverage, not vibes: if a check does not actually satisfy requirement text, leave `Checks: []` and mark it effectively MANUAL.
- Output formatter convention is non-negotiable: `{framework}.py` dispatcher only, `{framework}_{provider}.py` per-provider classes, `models.py` CSV schema, and `startswith("{framework}_")` registration everywhere.
- `{framework}.py` MUST NOT import `Finding` directly or transitively; keep anything touching `Finding` inside per-provider formatter files.
- Normalize `Attributes[0].FamilyName` and `Attributes[0].Section`; inconsistent values fragment the UI tree.

## Decision Gates

| Question | Action |
|---|---|
| Syncing from an upstream catalog? | Use the config-driven runner in `assets/sync_framework.py`; add or adapt parser/config instead of ad-hoc scripts. |
| Attribute payload does not fit an existing model? | Add a framework-specific attribute model in `compliance_models.py`, keeping `Generic` last. |
| Requirement IDs changed upstream? | Preserve mappings by configured fallback keys; do not silently mutate IDs without a parser rule and pre-validation. |
| Adding a new framework-specific CSV/table output? | Create per-provider formatter files, register CLI/API dispatchers with `startswith`, and add tests/fixtures. |
| Reviewing mappings as a cloud auditor? | Replace full requirement mappings explicitly; do not patch partial add/remove deltas. |
| No real automated coverage exists for a requirement? | Return an empty checks list instead of padded tangential mappings. |

## Execution Steps

1. Identify which layer is changing and read the adjacent code before editing: models, JSON catalogs, formatter dispatchers, API export map, and UI mapper if applicable.
2. For framework syncs, cache upstream data locally, run `assets/sync_framework.py` with a framework config, and keep parser quirks inside `assets/parsers/{name}.py`.
3. Validate emitted JSON with `prowler.lib.check.compliance_models.Compliance.parse_file(...)`; if validation fails, fix the payload or extend the typed attribute model.
4. Build a per-provider check inventory from `prowler/providers/{provider}/services/**/*.metadata.json` and abort on stale or misspelled check IDs.
5. For audits, query existing checks, dump affected requirement sections, and encode full REPLACE decisions; empty lists are valid when Prowler lacks honest coverage.
6. For new output formatters, mirror `c5`/`ens` structure: dispatcher, per-provider classes, CSV models, CLI registration in `prowler/lib/outputs/compliance/compliance.py`, CLI writer branches in `prowler/__main__.py`, and API export registration in `api/src/backend/tasks/jobs/export.py`.
7. Re-check UI grouping assumptions (`FamilyName`, `Section`) and versioned framework naming before finishing.

## Output Contract

- State which compliance layer(s) changed.
- Call out whether the work was a sync, audit, model extension, or formatter registration.
- Explicitly report check-ID validation status and any requirements intentionally left manual.
- If formatter code changed, list every registration surface updated: CLI dispatcher, CLI writer, API export map, and tests.
- Mention any invariants preserved: `Generic` last, non-empty `Version`, `startswith` dispatch, per-provider formatter split, or UI normalization.

## References

- `prowler/lib/check/compliance_models.py`
- `prowler/lib/check/compliance.py`
- `prowler/compliance/{provider}/`
- `prowler/lib/outputs/compliance/compliance.py`
- `prowler/__main__.py`
- `api/src/backend/tasks/jobs/export.py`
- `ui/lib/compliance/compliance-mapper.ts`
- `skills/prowler-compliance/assets/sync_framework.py`
- `skills/prowler-compliance/assets/configs/ccc.yaml`
- `skills/prowler-compliance/assets/parsers/finos_ccc.py`
- `skills/prowler-compliance/assets/audit_framework_template.py`
- `skills/prowler-compliance/assets/query_checks.py`
- `skills/prowler-compliance/assets/dump_section.py`
- `skills/prowler-compliance/references/compliance-docs.md`
- `skills/prowler-compliance-review/SKILL.md`
