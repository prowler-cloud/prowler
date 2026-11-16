---
name: prowler-compliance
description: >
  Creates, syncs, audits and maintains Prowler compliance frameworks: universal
  multi-provider JSON (preferred) and legacy per-provider JSON, ConfigRequirements
  guardrails, output formatters, external compliance plug-ins (entry points), and
  check-to-requirement mapping audits.
  Trigger: When working with compliance frameworks (CIS, CIS Controls, NIST,
  PCI-DSS, SOC2, GDPR, ISO27001, ENS, MITRE ATT&CK, CCC, C5, CSA CCM, DORA, CMMC,
  Cyber Essentials, FedRAMP 20x, KISA ISMS-P, ASD Essential Eight, DISA STIG,
  CISA SCuBA, SecNumCloud, HIPAA, NIS2, Prowler ThreatScore), creating a universal
  framework, adding ConfigRequirements guardrails, syncing with upstream catalogs,
  auditing check mappings, adding output formatters, or fixing compliance JSON bugs.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.1"
  scope: [root, sdk]
  auto_invoke:
    - "Creating/updating compliance frameworks"
    - "Creating a universal (multi-provider) compliance framework"
    - "Mapping checks to compliance controls"
    - "Adding ConfigRequirements guardrails to compliance requirements"
    - "Syncing compliance framework with upstream catalog"
    - "Auditing check-to-requirement mappings as a cloud auditor"
    - "Adding a compliance output formatter (per-provider class + table dispatcher)"
    - "Fixing compliance JSON bugs (duplicate IDs, empty Section, stale refs)"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

- Creating a framework (decide universal vs legacy first), adding requirements or providers to one
- Mapping checks, adding `ConfigRequirements` guardrails, auditing existing mappings
- Syncing with an upstream catalog, adding a legacy output formatter, fixing JSON bugs
- Explaining why a finding does not show under a framework (CLI, API or UI)

For reviewing a compliance PR use [prowler-compliance-review](../prowler-compliance-review/SKILL.md).
Contributor doc: `docs/developer-guide/security-compliance-framework.mdx`.

## Universal vs Legacy: decide first

Both formats load into the universal `ComplianceFramework` model (legacy via `adapt_legacy_to_universal()`).
The difference is authoring cost.

| | Universal (default for new frameworks) | Legacy per-provider |
|---|---|---|
| Location | `prowler/compliance/<framework>_<version>.json` | `prowler/compliance/<provider>/<framework>_<version>_<provider>.json` |
| Providers | Any, in one file (`checks: {provider: [...]}`) | One per file |
| Keys | lowercase (`framework`, `requirements`, `checks`) | Capitalized (`Framework`, `Requirements`, `Checks`) |
| Attribute schema | Declared in-file (`attributes_metadata`), validated at load | Pydantic class in `compliance_models.py` |
| CLI table/CSV/OCSF | Data driven from `outputs.table_config`, no Python | Formatter package + registrations |
| Guardrails | `config_requirements` (+ `Provider` on each) | `ConfigRequirements` |
| Shipped (5.48) | `cis_controls_8.1`, `cmmc_2.0`, `csa_ccm_4.0`, `cyber_essentials_3.3`, `dora_2022_2554`, `fedramp_20x_frr_class_c_2026`, `fedramp_20x_ksi_2026` | Everything under provider dirs |

Use **legacy only** to extend an existing legacy family (new CIS version for a provider that already has
CIS, ENS for a new provider). Everything else, including single-provider frameworks, is universal.

## Files a new framework needs

| Piece | Universal | Legacy (new family member) |
|---|---|---|
| JSON | `prowler/compliance/<key>.json` | `prowler/compliance/<provider>/<key>.json` |
| Attribute model | none (`attributes_metadata`) | existing class, or new class before Generic in the Union |
| CLI table / CSV / OCSF | none (needs `outputs.table_config`) | reuse family package; new provider = `{framework}_{provider}.py` + `models.py` row + branch in `prowler/__main__.py` |
| API compliance CSV | none (auto via `process_universal_compliance_frameworks`) | `COMPLIANCE_CLASS_MAP` entry in `api/src/backend/tasks/jobs/export.py` (else `GenericCompliance`) |
| API PDF | only if required: generator + `FRAMEWORK_REGISTRY` + `report.py` wiring | same |
| UI | optional: mapper + `getComplianceMappers()` entry keyed by `framework`, detail panel, type, icon | same; unknown frameworks use the generic mapper |
| Dashboard | optional (`dashboard/compliance/generic.py` fallback) | optional |
| Changelog | `prowler/changelog.d/<slug>.added.md` (towncrier fragment, not `CHANGELOG.md`) | same |

## Critical Rules

1. **Universal files need `outputs.table_config`** (`group_by` = a declared attribute key). Without it the
   framework loads and lists but produces no compliance CSV, OCSF or table.
2. **Declare `attributes_metadata`** with `required`/`enum` where possible. If it is missing nothing is
   validated; when present, unknown keys are rejected.
3. **Set `version`/`Version` for any versioned framework.** `get_check_compliance()` keys legacy findings
   `"{Framework}-{Version}"`, or just `"{Framework}"` when Version is empty (31 unversioned legacy files ship
   that way, e.g. `hipaa_aws`, `soc2_aws`, `mitre_attack_aws`). Changing Version on an existing file changes
   that key. Keep the filename version equal to `Version` (the CIS table matches
   `compliance_framework.split("_")[1]` against `Version`).
4. **Provider keys** in universal `checks` are lowercase directory names under `prowler/providers/`.
   Extending to a provider = adding a key. Every `config_requirements` entry carries `Provider`.
5. **Generic stays LAST** in `Compliance_Requirement.Attributes` (Pydantic v1 tries members in order).
   `compliance_models.py` uses `pydantic.v1` only.
6. **Loaders differ.** `Compliance.get_bulk()` sees only provider dirs and exits on a broken built-in file;
   the universal loader also reads top-level files and logs-and-skips broken ones. A framework that
   "disappears" was usually skipped: check the log.
7. **Universal-only frameworks are not in `CheckMetadata.Compliance`**, so they do not appear in the
   per-finding compliance field of regular outputs; they get their own compliance CSV + OCSF files.
8. **Include every requirement of the source catalog.** Empty `checks` = manual. Do not pad with tangential
   checks: honest MANUAL beats fake coverage.
9. **Legacy table modules must not import `Finding`** (circular import through `get_check_compliance`); use
   `TYPE_CHECKING` or function-local imports. CSV row field names in `models.py` are public API.
10. **`pdf_config` is not consumed** by the API; PDFs come from the hardcoded `FRAMEWORK_REGISTRY`
    (`prowler_threatscore`, `ens`, `nis2`, `csa_ccm`, `cis`).
11. **UI groups on `attributes[0]` values** (`Section`/`SubSection`, `Category`, `FamilyName` depending on the
    mapper). Normalize spelling or the tree splits.
12. **Icons**: `COMPLIANCE_LOGOS` in `IconCompliance.tsx` is an ordered substring match (`essentials` before
    `essential`, `cisa` before `cis`, `nist` before `nis2`).

Schemas, field tables and guardrail operators: [references/schema-reference.md](references/schema-reference.md).
Loaders, dispatch, API/UI internals: [references/compliance-docs.md](references/compliance-docs.md).

## Minimal universal framework

```json
{
  "framework": "My-Framework",
  "name": "My Framework 1.0",
  "version": "1.0",
  "description": "...",
  "attributes_metadata": [
    {"key": "Section", "type": "str", "required": true},
    {"key": "Service", "type": "str"}
  ],
  "outputs": {"table_config": {"group_by": "Section"}},
  "requirements": [
    {
      "id": "MF-1.1",
      "name": "Root MFA",
      "description": "Root account must have MFA enabled.",
      "attributes": {"Section": "IAM", "Service": "iam"},
      "checks": {"aws": ["iam_root_mfa_enabled"], "azure": []}
    }
  ]
}
```

Real templates: `prowler/compliance/dora_2022_2554.json`, `csa_ccm_4.0.json`, `cmmc_2.0.json`.
Legacy templates: [assets/](assets/) (`cis_framework.json`, `ens_framework.json`, `iso27001_framework.json`,
`mitre_attack_framework.json`, `prowler_threatscore_framework.json`, `generic_framework.json`).

## Workflows

### New universal framework

1. Write `prowler/compliance/<framework>_<version>.json` (key = basename).
2. `attributes_metadata` + `outputs.table_config.group_by`.
3. Map checks per provider (verify ids, see Validation); `config_requirements` with `Provider` for
   configurable checks; empty lists for manual requirements.
4. Validate. No Python is needed for CLI table/CSV/OCSF or the API CSV export.
5. Optional UI mapper/detail panel/type/icon, optional PDF generator.
6. Changelog fragment; user guide under `docs/user-guide/compliance/` for high-profile frameworks.

### New legacy formatter (existing legacy family, new framework package)

1. `prowler/lib/outputs/compliance/{framework}/` with `__init__.py`, `{framework}.py` (copy `c5/c5.py`,
   rename function and framework string), `models.py` (one row model per provider),
   `{framework}_{provider}.py` (`ComplianceOutput` subclass with `transform()`).
2. Register: `display_compliance_table()` branch in `compliance.py`, per-provider branch in
   `prowler/__main__.py`, `COMPLIANCE_CLASS_MAP` in `api/src/backend/tasks/jobs/export.py` (`startswith` for
   anything versionable).
3. Tests in `tests/lib/outputs/compliance/{framework}/` with fixtures in
   `tests/lib/outputs/compliance/fixtures.py` (one evaluated + one manual requirement).

### Sync with upstream

Config-driven runner in `assets/` (writes legacy JSON):
[references/upstream-sync.md](references/upstream-sync.md).

### Audit check mappings (cloud auditor)

Golden rule: a check's title/risk must literally verify what the requirement text says; otherwise MANUAL.

```bash
python skills/prowler-compliance/assets/build_inventory.py aws          # /tmp/checks_aws.json
python skills/prowler-compliance/assets/query_checks.py aws encryption transit
python skills/prowler-compliance/assets/query_checks.py aws --service iam
python skills/prowler-compliance/assets/dump_section.py cis_5.0_aws "1."   # legacy files only
```

Encode decisions as full REPLACE lists in a copy of `assets/audit_framework_template.py` (missing provider key =
untouched, `[]` = explicitly manual), abort on unknown check ids, then validate. Curated mappings and controls
Prowler cannot verify: [references/check-mapping-reference.md](references/check-mapping-reference.md)
(entries with `*` are patterns, expand them before use).

## Validation (run before every commit)

```bash
# 1. Load (both formats). The universal loader returns None on error instead of raising.
uv run python -c "from prowler.lib.check.compliance_models import load_compliance_framework_universal as l; \
fw=l('prowler/compliance/<file>.json'); assert fw, 'see log'; print(fw.framework, len(fw.requirements), fw.get_providers())"

# 2. Catalog integrity for every JSON: unique ids, no repeated checks, every check exists for its provider
uv run pytest tests/lib/check/compliance_catalog_integrity_test.py -k "<file_basename>" -q

# 3. Model/output suites (test_loads_as_universal is parametrized over every shipped JSON)
uv run pytest -n auto tests/lib/check/ tests/lib/outputs/compliance/ -q

# 4. CLI smoke test (listing needs no credentials)
uv run python prowler-cli.py <provider> --list-compliance | grep <key>
uv run python prowler-cli.py <provider> --list-compliance-requirements <key>
uv run python prowler-cli.py <provider> --compliance <key>    # real scan: check output/compliance/
```

CI and hooks: `prek` runs `check-json` and `pretty-format-json` (format only, no semantics).
`.github/workflows/pr-check-compliance-mapping.yml` adds `needs-compliance-review` to PRs that add checks
not mapped to any framework (skip with label `no-compliance-check`).

## Commands

```bash
prowler <provider> --list-compliance
prowler <provider> --list-compliance-requirements <key>
prowler aws --compliance cis_7.0_aws pci_4.0_aws
prowler aws --compliance dora_2022_2554          # universal key = file basename
prowler aws --compliance cis_7.0_aws -M csv json-ocsf html
```

`--compliance` is mutually exclusive with `--check`, `--service`, `--checks-file` and `--category`.

## External compliance plug-ins

Packages can contribute frameworks through Python entry points, no core change needed:
`prowler.compliance` (legacy JSONs, entry point name = provider key) and `prowler.compliance.universal`
(universal JSONs). Built-ins win on name collisions; invalid external files are skipped with a warning.
Details: [references/compliance-docs.md](references/compliance-docs.md#external-compliance-plug-ins-entry-points).
Packaging and publishing the plug-in: [prowler-registry-artifact](../prowler-registry-artifact/SKILL.md).

## Resources

- **References**: [schema-reference.md](references/schema-reference.md),
  [compliance-docs.md](references/compliance-docs.md) (architecture, loaders, API/UI, one-liners),
  [upstream-sync.md](references/upstream-sync.md),
  [check-mapping-reference.md](references/check-mapping-reference.md)
- **Assets**: sync runner (`sync_framework.py`, `configs/ccc.yaml`, `parsers/finos_ccc.py`), audit tooling
  (`build_inventory.py`, `query_checks.py`, `dump_section.py`, `audit_framework_template.py`), legacy JSON
  templates
- **Docs**: `docs/developer-guide/security-compliance-framework.mdx`,
  `docs/user-guide/compliance/tutorials/compliance.mdx`, `cross-provider-compliance.mdx`
- **Sister skill**: [prowler-compliance-review](../prowler-compliance-review/SKILL.md)
