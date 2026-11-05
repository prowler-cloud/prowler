---
name: prowler-compliance-review
description: >
  Reviews Pull Requests that add or modify Prowler compliance frameworks (universal
  multi-provider or legacy per-provider JSON, mappings, guardrails, formatters).
  Trigger: When reviewing PRs with compliance framework changes, CIS/NIST/PCI-DSS additions, or compliance JSON files.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, sdk]
  auto_invoke: "Reviewing compliance framework PRs"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

- Reviewing PRs that add, extend or modify compliance frameworks under `prowler/compliance/`
- Reviewing check-mapping changes, `ConfigRequirements` guardrails, or new compliance formatters

For authoring rules and the schema, load [prowler-compliance](../prowler-compliance/SKILL.md).

## Identify the schema first

| File | Schema | Expect in the PR |
|---|---|---|
| `prowler/compliance/<key>.json` (top level, lowercase keys) | Universal | JSON only (+ optional UI mapper/panel/icon). No Python formatter, no `COMPLIANCE_CLASS_MAP` entry |
| `prowler/compliance/<provider>/<key>.json` (Capitalized keys) | Legacy | JSON; plus formatter + `__main__.py` branch + `COMPLIANCE_CLASS_MAP` entry only if a new framework family/provider writer is introduced |

A brand-new framework submitted as legacy is a REQUEST CHANGES unless it extends an existing legacy family.

## Review Checklist

| Check | How | Pass criteria |
|---|---|---|
| Loads | `load_compliance_framework_universal()` one-liner below | Not `None` (universal loader swallows errors, check the log) |
| Catalog integrity | `uv run pytest tests/lib/check/compliance_catalog_integrity_test.py -k <basename>` | Unique ids, no repeated checks, every check exists for its provider |
| Structure | `validate_compliance.py <file>` | No errors (both schemas) |
| `outputs.table_config` (universal) | validator | Present, `group_by` declared in `attributes_metadata` |
| `attributes_metadata` (universal) | read | Present, `required`/`enum` used for closed sets |
| Guardrails | read | Universal: `Provider` on every `config_requirements` entry. Value = strictest the control allows; `ConfigKey` exists in the check |
| Version | read | Set for versioned frameworks; filename version equals `Version` |
| Mapping quality | sample requirements vs check titles | Check literally verifies the requirement; otherwise `[]` (manual). No padding |
| Completeness | compare with source | Every source requirement present, including manual ones |
| Grouping values | `jq '[.Requirements[].Attributes[0].Section] \| unique'` (legacy) | No spelling variants (they split the UI tree) |
| Tests | `uv run pytest -n auto tests/lib/check/ tests/lib/outputs/compliance/ -q` | Green |
| Changelog | PR diff | Fragment `prowler/changelog.d/<slug>.<type>.md`, no direct `CHANGELOG.md` edit |

Dashboard files (`dashboard/compliance/<key with dots as underscores>.py`) are optional: the local dashboard
falls back to `dashboard/compliance/generic.py`. Do not request one.

## Commands

```bash
# Structure + check existence (legacy and universal)
python3 skills/prowler-compliance-review/assets/validate_compliance.py prowler/compliance/<path>.json

# Load with the real model (prints framework, requirement count, providers)
uv run python -c "from prowler.lib.check.compliance_models import load_compliance_framework_universal as l; \
fw=l('prowler/compliance/<path>.json'); assert fw, 'see log'; print(fw.framework, len(fw.requirements), fw.get_providers())"

# Repo integrity tests for this file
uv run pytest tests/lib/check/compliance_catalog_integrity_test.py -k "<basename>" -q

# CLI: listed and requirements visible (no credentials needed)
uv run python prowler-cli.py <provider> --list-compliance | grep <key>
uv run python prowler-cli.py <provider> --list-compliance-requirements <key>

# Full run against a real account (writes output/compliance/)
uv run python prowler-cli.py <provider> --compliance <key> -M csv json-ocsf html
```

`--compliance` cannot be combined with `--check`, `--service`, `--checks-file` or `--category` (mutually
exclusive argparse group).

## Decision Tree

```text
Loads with the real model?            No  -> FAIL
Integrity test / validator errors?    Yes -> FAIL (missing checks, duplicate ids, missing table_config...)
New framework authored as legacy?     Yes -> REQUEST CHANGES (use universal) unless extending a legacy family
Mappings padded or requirements missing? Yes -> REQUEST CHANGES
Changelog fragment missing?           Yes -> REQUEST CHANGES
Otherwise                             -> APPROVE
```

## Common Issues

| Issue | Detect | Resolution |
|---|---|---|
| Typo in check id | integrity test / validator | Fix id or remove it |
| Universal file without `table_config` | validator | Add `outputs.table_config.group_by` |
| Unknown attribute key | loader returns `None`, log says `unknown attribute` | Declare it in `attributes_metadata` or fix the key |
| Uppercase provider key in `checks` | validator | Use `prowler/providers/` directory names |
| Guardrail without `Provider` in universal file | validator | Add `Provider` |
| Automated requirement with no checks (CIS-style) | validator warning | Add checks or mark Manual |
| Manual edit of `CHANGELOG.md` | diff | Move to a `changelog.d` fragment |

## Resources

- **Validator**: [assets/validate_compliance.py](assets/validate_compliance.py)
- **Summary template and file locations**: [references/review-checklist.md](references/review-checklist.md)
- **Authoring skill**: [prowler-compliance](../prowler-compliance/SKILL.md)
- **Docs**: `docs/developer-guide/security-compliance-framework.mdx`
