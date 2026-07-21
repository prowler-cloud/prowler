---
name: prowler-compliance
description: >
  Creates, syncs, audits and manages Prowler compliance frameworks end-to-end.
  Covers the two supported JSON schemas (universal multi-provider and legacy
  per-provider), the SDK model tree (legacy attribute classes, universal
  ComplianceFramework, ConfigRequirements guardrails), output formatters
  (legacy per-framework + universal data-driven), API/UI consumption, upstream
  sync workflows, and cloud-auditor check-mapping reviews.
  Trigger: When working with compliance frameworks (CIS, CIS Controls, NIST,
  PCI-DSS, SOC2, GDPR, ISO27001, ENS, MITRE ATT&CK, CCC, C5, CSA CCM, DORA,
  KISA ISMS-P, ASD Essential Eight, DISA STIG, CISA SCuBA, SecNumCloud,
  FedRAMP, HIPAA, NIS2, Prowler ThreatScore), creating a universal
  multi-provider framework, adding ConfigRequirements guardrails, syncing with
  upstream catalogs, auditing check-to-requirement mappings, adding output
  formatters, or fixing compliance JSON bugs (duplicate IDs, empty Version,
  wrong Section, stale check refs).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
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

Use this skill when:

- Creating a new compliance framework for any provider — **decide universal vs legacy first** (see below)
- **Syncing an existing framework with an upstream source of truth** (CIS, FINOS CCC, CSA CCM, NIST, ENS, etc.)
- Adding requirements to existing frameworks, or extending a universal framework to a new provider
- Mapping checks to compliance controls
- **Adding `ConfigRequirements` guardrails** so configurable checks can't silently satisfy a requirement with a loosened config
- **Auditing existing check mappings as a cloud auditor** ("are these mappings correct?", "which checks apply?", "review the mappings")
- **Adding a new legacy output formatter** (table dispatcher + per-provider classes + CSV models)
- **Fixing JSON bugs**: duplicate IDs, empty Version, wrong Section, stale check refs, inconsistent FamilyName, padded tangential check mappings
- Investigating why a finding/check isn't showing under the expected compliance framework in the UI
- Understanding compliance framework structures and attributes

The authoritative contributor doc is `docs/developer-guide/security-compliance-framework.mdx` —
keep this skill and that doc consistent when either changes. For **reviewing**
a compliance PR, use the sister skill
[prowler-compliance-review](../prowler-compliance-review/SKILL.md) instead.

## Universal vs Legacy: The First Decision

Prowler supports **two JSON schemas**. Choosing wrong means unnecessary Python
code, so decide this before anything else. At load time both converge: legacy
files are adapted into the universal `ComplianceFramework` model
(`adapt_legacy_to_universal()`), so the difference is about **authoring cost
and capabilities**, not about what the rest of Prowler sees.

### Side-by-side comparison

| | Universal (recommended for new frameworks) | Legacy provider-specific |
|---|---|---|
| File location | `prowler/compliance/<framework>.json` (top level) | `prowler/compliance/<provider>/<framework>_<version>_<provider>.json` |
| Providers | Any number, one file (`checks` dict keyed by provider) | Exactly one provider per file (one file per provider to multi-cover) |
| Key style | lowercase (`framework`, `requirements`, `checks`) | Capitalized (`Framework`, `Requirements`, `Checks`) |
| Attribute schema | Declared **in the JSON itself** via `attributes_metadata`, validated at load | Pydantic class per framework family in `compliance_models.py` (code change for new shapes) |
| Attributes per requirement | One flat dict (`attributes: {...}`) | List of objects (`Attributes: [{...}]`) — only `Attributes[0]` is used downstream |
| Table/CSV/OCSF output | Data-driven from `outputs.table_config` — **zero Python changes** | Formatter package + registrations in `compliance.py`, `__main__.py`, `export.py` |
| Guardrails field | `config_requirements` (+ mandatory `Provider` per constraint) | `ConfigRequirements` (`Provider` omitted) |
| Loader behavior on error | Lenient: logs + skips file (`load_compliance_framework_universal`) | Fail-fast: `sys.exit(1)` (`load_compliance_framework`) |
| Loaded by | Only `get_bulk_compliance_frameworks_universal()` | Both loaders (`Compliance.get_bulk()` + universal, via adapter) |
| Shipped examples | `cis_controls_8.1.json`, `csa_ccm_4.0.json`, `dora_2022_2554.json` | Everything else (~105 files across 11 providers) |

### When to use which

**Use universal when** (any of these):

- The framework is **new to Prowler** — no existing attribute class, no
  existing formatter. This is the default: zero Python changes needed.
- The framework spans (or will span) **more than one provider** — DORA, CSA
  CCM, CIS Controls. One file covers all providers; extending to a new
  provider is a one-line `checks` edit.
- The attribute shape is **unique to this framework** — declare it in
  `attributes_metadata` instead of adding a Pydantic class to the Union.

**Use legacy only when extending an existing legacy family**:

- A new **version** of a shipped legacy framework (CIS 8.0 for AWS → new
  `cis_8.0_aws.json`, same `CIS_Requirement_Attribute`, same `cis/` formatter).
- An existing legacy framework for a **new provider** (ENS for m365 → new
  `ens_rd2022_m365.json` + `ens_m365.py` transformer).
- Consistency with the family matters more than the universal benefits — a
  lone `cis_8.0_aws` in universal format while 20+ CIS files stay legacy
  would fragment the family.

**Never**: start a brand-new single-provider framework as legacy "because it's
only AWS today". Universal handles single-provider fine (the `checks` dict
just has one key) and you skip 3 output files + 3 registrations.

### The same requirement in both schemas

Universal (`prowler/compliance/my_framework_1.0.json`):

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
      "checks": {
        "aws": ["iam_root_mfa_enabled"],
        "azure": []
      }
    }
  ]
}
```

Legacy (`prowler/compliance/aws/my_framework_1.0_aws.json` — plus a second
file per extra provider, plus formatter + registrations):

```json
{
  "Framework": "My-Framework",
  "Name": "My Framework 1.0 for AWS",
  "Version": "1.0",
  "Provider": "AWS",
  "Description": "...",
  "Requirements": [
    {
      "Id": "MF-1.1",
      "Name": "Root MFA",
      "Description": "Root account must have MFA enabled.",
      "Attributes": [
        {"ItemId": "MF-1.1", "Section": "IAM", "Service": "iam"}
      ],
      "Checks": ["iam_root_mfa_enabled"]
    }
  ]
}
```

Same control, but the universal file already covers Azure, validates its own
attribute schema, and renders table/CSV/OCSF with no code. Field-by-field
references for each schema follow below.

## Architecture (Mental Model)

Prowler compliance is a four-layer system. Bugs usually happen where one layer
doesn't match another, so know all four before touching anything.

### Layer 1: SDK / Core Models — `prowler/lib/check/`

All in **Pydantic v1** (`from pydantic.v1 import ...`). Three model groups live
in `compliance_models.py`:

**Legacy tree** — `Compliance` → `Compliance_Requirement` / `Mitre_Requirement`:

- One `*_Requirement_Attribute` class per framework family. Registered today (Union order matters):
  `ASDEssentialEight`, `CIS`, `ENS`, `ISO27001_2013`, `AWS_Well_Architected`,
  `KISA_ISMSP`, `Prowler_ThreatScore`, `CCC`, `C5Germany`, `CSA_CCM`, `STIG`
  (Okta IDaaS), and `Generic_Compliance_Requirement_Attribute` as fallback.
- **Generic MUST stay LAST** in `Compliance_Requirement.Attributes: list[Union[...]]` —
  Pydantic v1 tries union members in order; Generic first would swallow every
  framework-specific attribute. NIST 800-53/CSF, PCI DSS, GDPR, HIPAA, SOC2,
  FedRAMP, SecNumCloud etc. intentionally use Generic.
- A `root_validator` rejects empty `Framework`, `Provider` or `Name`.
- MITRE uses the separate `Mitre_Requirement` model (`Tactics`, `SubTechniques`,
  `Platforms`, `TechniqueURL` at requirement top level, per-provider
  `Mitre_Requirement_Attribute_{AWS,Azure,GCP}`).

**Universal tree** — `ComplianceFramework` → `UniversalComplianceRequirement`:

- Flat `attributes: dict` per requirement, schema declared in
  `attributes_metadata` (key, label, type, enum, required, `enum_display`,
  `enum_order`, `output_formats`). A `root_validator` rejects missing required
  keys, unknown keys (drift guard), enum violations, and int/float/bool type
  mismatches. If `attributes_metadata` is omitted, **no validation runs**.
- `checks: dict[provider, list[check_id]]` — the provider list of the framework
  is **derived** from these keys (`get_providers()` / `supports_provider()`);
  the top-level `provider` field is only a fallback.
- `outputs.table_config` (group_by, split_by, scoring, labels) drives the CLI
  table; `outputs.pdf_config` exists in the model but **is not consumed by the
  API PDF pipeline yet** (see Layer 4).

**Guardrails** — `Compliance_Requirement_ConfigConstraint`:

- Fields `Check`, `ConfigKey`, `Operator` (`lte|gte|eq|in|subset|superset`),
  `Value`, optional `Provider` (required in universal multi-provider files).
- A `root_validator` rejects Value/Operator type mismatches at load time.
- Evaluation is centralized in `prowler/lib/check/compliance_config_eval.py`
  (`evaluate_config_constraints`, `apply_config_status`, `get_effective_status`,
  `CONFIG_NOT_VALID_PREFIX = "Configuration not valid for this requirement."`),
  shared by CSV/OCSF/table outputs **and** the API backend. A violated
  constraint forces the requirement to FAIL and prepends the reason to
  `status_extended`. Constraints whose `ConfigKey` is absent from
  `audit_config` are skipped (defaults assumed compliant).

**Loaders**:

- `Compliance.get_bulk(provider)` — legacy: scans only
  `prowler/compliance/{provider}/` (+ external JSONs via the
  `prowler.compliance` entry-point group). Does NOT see top-level universal files.
- `get_bulk_compliance_frameworks_universal(provider)` — scans **both** the
  top-level `prowler/compliance/` and every provider subdirectory, adapting
  legacy files via `adapt_legacy_to_universal()` (flattens `Attributes[0]` to a
  dict, wraps `Checks` as `{provider: [...]}`, infers `attributes_metadata`).
  Also loads external universal frameworks via the
  `prowler.compliance.universal` entry-point group (built-ins win collisions).
- `get_check_compliance(finding, provider_type, bulk_checks_metadata)` lives in
  **`prowler/lib/outputs/compliance/compliance_check.py`** (not in
  `lib/check/compliance.py`). It builds the per-finding dict keyed
  `f"{Framework}-{Version}"` **only when Version is non-empty** — an empty
  Version silently produces the key `"{Framework}"` and breaks downstream
  filters and tests.
- `prowler/lib/check/compliance.py` now contains only
  `update_checks_metadata_with_compliance()`.

### Layer 2: JSON Catalogs — `prowler/compliance/`

See "Compliance Catalog Coverage" below.

### Layer 3: Output Formatters — `prowler/lib/outputs/compliance/`

**Universal path** (no Python needed per framework):

- `universal/universal_table.py` — `get_universal_table()`, renders the CLI
  table from `outputs.table_config` + `attributes_metadata`.
- `universal/universal_output.py` — `UniversalComplianceOutput`, builds the CSV
  Pydantic model **dynamically** from `attributes_metadata`.
- `universal/ocsf_compliance.py` — `OCSFComplianceOutput`; OCSF output is
  **always generated** for universal frameworks regardless of `--output-formats`.
- Orchestrated by `process_universal_compliance_frameworks()` in
  `compliance.py`, which runs **before** any legacy dispatch and removes the
  processed frameworks from the set.

**Legacy path** — per-framework directory, usually:

```text
{framework}/
├── __init__.py
├── {framework}.py            # get_{framework}_table() summary-table function
├── {framework}_{provider}.py # One ComplianceOutput subclass per provider
└── models.py                 # One Pydantic CSV row model per provider
```

Directories today: `asd_essential_eight`, `aws_well_architected`, `c5`, `ccc`,
`cis`, `cisa_scuba`, `ens`, `generic`, `iso27001`, `kisa_ismsp`,
`mitre_attack`, `okta_idaas_stig`, `prowler_threatscore`, `universal`.
Known deviations (don't "fix" them without a reason): `iso27001/` has no table
file (falls to the generic table), `aws_well_architected/` has no per-provider
files, `cisa_scuba/` only ships googleworkspace.

- CSV writers emit `;`-delimited files with UPPERCASE headers
  (`ComplianceOutput.batch_write_data_to_file`). Field names in `models.py`
  are **public API** — renaming breaks downstream consumers.
- **Circular import rule**: the table file (`{framework}.py`) must not import
  `Finding` directly or transitively (`compliance.compliance` → table module →
  `ComplianceOutput` → `Finding` → `get_check_compliance` → cycle). Keep table
  files bare (`colorama`, `tabulate`, `prowler.config.config`); when a module
  genuinely needs both, use `if TYPE_CHECKING:` or function-local imports (see
  `universal_output.py` / `process_universal_compliance_frameworks`).
- Legacy table functions have no docstrings; the universal ones do. Match the
  style of the file family you're touching.
- Dispatcher `display_compliance_table()` in `compliance.py` order:
  universal (`table_config`) first → `cis_` → `ens_` → `mitre_attack` →
  `kisa` → `prowler_threatscore_` → `c5_` → `ccc_` → `asd_essential_eight`
  (substring) → `okta_idaas_stig` → else provider hook
  (`provider.display_compliance_table()`, may raise `NotImplementedError`) →
  `get_generic_compliance_table()`. iso27001, aws_well_architected and
  cisa_scuba ride the fallback on purpose.

### Layer 4: API / UI

- **API lazy loaders**: `api/src/backend/api/compliance.py` —
  `LazyComplianceTemplate` / `LazyChecksMapping` (per-provider lazy caches over
  `get_bulk_compliance_frameworks_universal`, with Gunicorn background warm-up).
- **API CSV export dispatch**: `COMPLIANCE_CLASS_MAP` in
  `api/src/backend/tasks/jobs/export.py`, consumed from `tasks/tasks.py`. It is
  a dict `provider → [(predicate, exporter_class)]` with `GenericCompliance` as
  fallback. Predicates mix **`startswith` for multi-version families**
  (`cis_`, `ens_`, `iso27001_`, `ccc_`, `cisa_scuba_`, ...) and **exact
  `name == ...` for true singletons** (`mitre_attack_aws`,
  `prowler_threatscore_*`, `asd_essential_eight_aws` — and inconsistently
  `c5_azure`/`c5_gcp`, while aws uses `startswith("c5_")`). Rule of thumb: if
  the framework can ever grow versions or variants, use `startswith`.
- **API overview ingestion**: `create_compliance_requirements()` in
  `api/src/backend/tasks/jobs/scan.py` builds per-region rows from the lazy
  template and persists `ComplianceRequirementOverview` (COPY with bulk-create
  fallback) plus `ComplianceOverviewSummary`.
- **API PDF reports**: `api/src/backend/tasks/jobs/reports/` — hardcoded
  `FRAMEWORK_REGISTRY` (own `FrameworkConfig` dataclass, NOT the SDK
  `PDFConfig`) with one generator class per framework. Only
  `prowler_threatscore`, `ens`, `nis2`, `csa_ccm` and `cis` have PDFs today;
  adding one means a generator class + registry entry + wiring in `report.py`.
- **UI mapper routing**: `ui/lib/compliance/compliance-mapper.ts` —
  `getComplianceMappers()` keyed by the JSON's `framework` value
  (e.g. `"CIS"`, `"CIS-Controls"`, `"DORA"`, `"Okta-IDaaS-STIG"`). Unregistered
  frameworks **fall back to the generic mapper + `GenericCustomDetails`
  automatically** — a dedicated mapper/detail panel is a first-class upgrade,
  not a requirement to render.
- **UI grouping varies per mapper**: generic/cis group by
  `Section`/`SubSection`, iso by `Category`, ccc by `FamilyName`. All read
  `attributes[0]` — inconsistent values within one JSON become separate tree
  branches, so normalize before shipping.
- **UI types**: `ui/types/compliance.ts` — one `*AttributesMetadata` interface
  per framework, added to the `AttributesItemData` metadata union.
- **UI icons**: `ui/components/icons/compliance/` + `IconCompliance.tsx`.
  Registration is an ordered substring match (`COMPLIANCE_LOGOS`): put
  framework-specific keywords **before** generic ones (`nist` before `nis2`,
  `cisa` before `cis`; `aws` deliberately last).

### The CLI Pipeline (end-to-end)

```text
prowler aws --compliance cis_7.0_aws          # framework key = JSON basename
    ↓
Compliance.get_bulk("aws")                      # legacy frameworks
get_bulk_compliance_frameworks_universal("aws") # legacy (adapted) + universal
    ↓
update_checks_metadata_with_compliance()        # attaches compliance to CheckMetadata
    ↓
execute_checks() → Finding objects
    ↓
get_check_compliance(finding, "aws", bulk)      # dict "{Framework}-{Version}" → [req_ids]
    ↓
process_universal_compliance_frameworks()       # universal: CSV + OCSF, then removed from set
per-provider elif branches in __main__.py       # legacy: AWSCIS(...).batch_write_data_to_file()
    ↓
display_compliance_table()                      # universal table first, then legacy elifs,
                                                # then generic fallback
```

---

## Compliance Catalog Coverage

Counts as of 2026-07 (109 JSON files). Regenerate before trusting them:

```bash
for d in prowler/compliance/*/; do printf "%s: %s\n" "$(basename $d)" "$(ls $d*.json 2>/dev/null | wc -l)"; done
ls prowler/compliance/*.json   # universal, top-level
```

**Universal (top-level, multi-provider)**: `cis_controls_8.1.json` (18
providers), `csa_ccm_4.0.json` (aws/azure/gcp/alibabacloud/oraclecloud),
`dora_2022_2554.json` (aws/azure/gcp/alibabacloud/cloudflare).

**Legacy per-provider** (families, not exhaustive versions):

| Provider | # | Framework families |
|---|---|---|
| aws | 45 | CIS 1.4–7.0, NIST 800-53 r4/r5, NIST 800-171 r2, NIST CSF 1.1/2.0, PCI 3.2.1/4.0, ISO 27001 2013/2022, HIPAA, GDPR, SOC2, FedRAMP low/moderate r4 + 20x KSI low, ENS RD2022, MITRE ATT&CK, C5, CCC, CISA, FFIEC, RBI, Well-Architected (security/reliability), FTR, FSBP, AWS AI Security Framework, AWS Account Security Onboarding, Audit Manager Control Tower, GxP 21 CFR 11 / EU Annex 11, KISA ISMS-P 2023 (en+ko), NIS2, ASD Essential Eight, SecNumCloud 3.2, Prowler ThreatScore |
| azure | 19 | CIS 2.0–6.0, ISO 27001 2022, ENS RD2022, MITRE ATT&CK, PCI 4.0, HIPAA, SOC2, NIS2, RBI, C5, CCC, FedRAMP 20x KSI low, SecNumCloud 3.2, Prowler ThreatScore |
| gcp | 17 | CIS 2.0–5.0, ISO 27001 2022, ENS RD2022, MITRE ATT&CK, PCI 4.0, HIPAA, SOC2, NIS2, RBI, C5, CCC, FedRAMP 20x KSI low, SecNumCloud 3.2, Prowler ThreatScore |
| kubernetes | 8 | CIS 1.8–2.0.1, ISO 27001 2022, PCI 4.0, Prowler ThreatScore |
| m365 | 5 | CIS 4.0/6.0/7.0, ISO 27001 2022, Prowler ThreatScore |
| alibabacloud | 3 | CIS 2.0, SecNumCloud 3.2, Prowler ThreatScore |
| oraclecloud | 3 | CIS 3.0/3.1, SecNumCloud 3.2 |
| github | 2 | CIS 1.0/1.2.0 |
| googleworkspace | 2 | CIS 1.3, CISA SCuBA 0.6 |
| okta | 1 | Okta IDaaS STIG V1R2 |
| nhn | 1 | ISO 27001 2022 |

Providers with a compliance directory but no frameworks yet: cloudflare, iac,
linode, llm, mongodbatlas, openstack, stackit. Provider keys inside universal
`checks` dicts must match directory names under `prowler/providers/` (lowercase).

---

## Universal Schema Reference

Full spec in `docs/developer-guide/security-compliance-framework.mdx`. Skeleton:

```json
{
  "framework": "DORA",
  "name": "Digital Operational Resilience Act (DORA) 2022/2554",
  "version": "2022/2554",
  "description": "Shown in --list-compliance and PDF reports.",
  "icon": "dora",
  "attributes_metadata": [
    {"key": "Pillar", "label": "Pillar", "type": "str", "required": true,
     "enum": ["ICT Risk Management", "..."],
     "output_formats": {"csv": true, "ocsf": true}},
    {"key": "Article", "type": "str", "required": true}
  ],
  "outputs": {
    "table_config": {"group_by": "Pillar"},
    "pdf_config": {"group_by_field": "Pillar", "charts": ["..."]}
  },
  "requirements": [
    {
      "id": "DORA-Art5",
      "name": "Governance and organisation",
      "description": "Requirement text verbatim from the source.",
      "attributes": {"Pillar": "ICT Risk Management", "Article": "Article 5"},
      "checks": {
        "aws": ["iam_no_root_access_key"],
        "azure": [],
        "gcp": []
      },
      "config_requirements": [
        {"Check": "iam_user_accesskey_unused", "Provider": "aws",
         "ConfigKey": "max_unused_access_keys_days", "Operator": "lte", "Value": 45}
      ]
    }
  ]
}
```

### Universal fields, top level (`ComplianceFramework`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `framework` | string | Yes | Short identifier (`DORA`, `CSA-CCM`, `CIS-Controls`). This is the key the UI mapper routes on. |
| `name` | string | Yes | Human-readable full name. |
| `version` | string | No (never leave empty) | Framework version/edition (`8.1`, `2022/2554`). |
| `description` | string | Yes | Shown in `--list-compliance` and PDF reports. |
| `provider` | string | No | Fallback only — the effective provider list is derived from `checks` keys across requirements (`get_providers()`). |
| `icon` | string | No | Short icon slug. |
| `attributes_metadata` | array | No (strongly recommended) | Declares the schema of every `attributes` key. **If omitted, no attribute validation runs at all.** |
| `outputs` | object | No | `table_config` (CLI table) + `pdf_config` (modeled, not yet consumed by the API). |
| `requirements` | array | Yes | List of requirement objects (below). |

### Universal fields, per requirement (`UniversalComplianceRequirement`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | Yes | Unique within the framework. |
| `description` | string | Yes | Requirement text verbatim from the source. |
| `name` | string | No | Short title. |
| `attributes` | dict | No (default `{}`) | Flat dict; every key must be declared in `attributes_metadata` (unknown keys are rejected at load when metadata exists). |
| `checks` | dict | No (default `{}`) | `{provider: [check_ids]}`, lowercase keys matching `prowler/providers/` dirs. Empty list = manual requirement for that provider. |
| `config_requirements` | array | No | Guardrails; each constraint **must** carry `Provider`. |
| `tactics`, `sub_techniques`, `platforms`, `technique_url` | — | No | MITRE-style extras (auto-populated when adapting legacy MITRE files). |

### `attributes_metadata` entry fields (`AttributeMetadata`)

| Field | Type | Notes |
|---|---|---|
| `key` | string (required) | Attribute name as used in `requirement.attributes`. |
| `label` | string | Human-readable label for CSV headers / PDF. |
| `type` | string | `str` (default), `int`, `float`, `bool`, `list_str`, `list_dict`. Only int/float/bool are enforced at load; the rest are documentation. |
| `enum` | list | Allowed values — enforced at load. Use it whenever the value set is closed. |
| `required` | bool | Enforced at load: every requirement must carry the key non-null. |
| `enum_display` / `enum_order` | dict / list | Per-enum-value visual metadata (label, abbreviation, color, icon) and ordering for PDF rendering. |
| `chart_label` | string | Axis label when the attribute is used in charts. |
| `output_formats` | object | `{"csv": bool, "ocsf": bool}`, both default `true` — toggles inclusion per output. |

Key rules:

- `--compliance` key = JSON basename without `.json` (`dora_2022_2554`).
- Auto-discovered: no `__init__.py`, no formatter, no dispatcher registration.
- `table_config.group_by`, `pdf_config.group_by_field` and every
  `charts[].group_by` must reference a key declared in `attributes_metadata`.
- Runtime type validation only covers `int`/`float`/`bool`; `str`/`list_str`/
  `list_dict` are documentation-only.
- Extending to a new provider = adding a key to `requirement.checks`. Nothing else.
- **No automatic check-existence validation at load time** — a typo'd check id
  silently produces a requirement with no findings. Always run the
  check-existence cross-check (see Validation).
- In universal files, always set `Provider` on every config constraint so a
  guardrail authored for an AWS check never affects Azure/GCP scans of the
  same requirement.

## Legacy Schema Reference

Base legacy file structure:

```json
{
  "Framework": "FRAMEWORK_NAME",
  "Name": "Full Framework Name with Version",
  "Version": "X.X",
  "Provider": "AWS",
  "Description": "Framework description...",
  "Requirements": [
    {
      "Id": "requirement_id",
      "Name": "Optional requirement name",
      "Description": "Requirement description",
      "Attributes": [ ... ],
      "Checks": ["check_name_1"],
      "ConfigRequirements": [ ... ]
    }
  ]
}
```

### Legacy fields, top level (`Compliance`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `Framework` | string | Yes (non-empty, validated) | Canonical identifier (`CIS`, `ENS`, `NIST-800-53-Revision-5`). |
| `Name` | string | Yes (non-empty, validated) | Human-readable name with version. |
| `Version` | string | Optional in the model — **never leave it empty in practice** | Empty Version silently degrades the `get_check_compliance()` key to `"{Framework}"` (gotcha #4). Must match the version substring in the filename. |
| `Provider` | string | Yes (non-empty, validated) | Upper-cased single provider (`AWS`, `AZURE`, `GCP`, `M365`, ...). One file = one provider. |
| `Description` | string | Yes | Framework scope and purpose. |
| `Requirements` | array | Yes | Requirement objects (below), or `Mitre_Requirement` objects for MITRE files. |

### Legacy fields, per requirement (`Compliance_Requirement`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `Id` | string | Yes | Unique within the framework; follow the source numbering exactly (`1.1`, `A.5.1`, `CCC.Core.CN01.AR01`). |
| `Description` | string | Yes | Verbatim from the source catalog. |
| `Name` | string | No | Optional short title (NIST-style catalogs use it). |
| `Attributes` | array of objects | Yes | Parsed against the Union of attribute classes below; only `Attributes[0]` survives the universal adaptation and drives UI grouping. |
| `Checks` | array of strings | Yes | Check ids automating the requirement; `[]` = manual. |
| `ConfigRequirements` | array | No | Guardrails; `Provider` is omitted (the file is single-provider). |

MITRE files use `Mitre_Requirement` instead, which adds `Tactics`,
`SubTechniques`, `Platforms`, `TechniqueURL` at the requirement top level.

### Attribute shapes per framework family

Unlike universal (schema in-file), a legacy requirement's `Attributes` must
match one of the Pydantic classes registered in
`Compliance_Requirement.Attributes` — a shape matching no class **silently
falls through to Generic**, dropping its specific fields. The most common
shapes (full field sets in `compliance_models.py`):

### CIS — `cis_{version}_{provider}`

```json
{
  "Section": "1 Identity and Access Management",
  "SubSection": "Optional subsection",
  "Profile": "Level 1",
  "AssessmentStatus": "Automated",
  "Description": "...", "RationaleStatement": "...", "ImpactStatement": "...",
  "RemediationProcedure": "...", "AuditProcedure": "...",
  "AdditionalInformation": "...", "DefaultValue": "...", "References": "https://..."
}
```

`Profile`: `Level 1|Level 2|E3 Level 1|E3 Level 2|E5 Level 1|E5 Level 2`.
`AssessmentStatus`: `Automated|Manual`.

### ENS — `ens_rd2022_{provider}`

```json
{
  "IdGrupoControl": "op.acc.1", "Marco": "operacional",
  "Categoria": "control de acceso", "DescripcionControl": "...",
  "Nivel": "alto", "Tipo": "requisito",
  "Dimensiones": ["trazabilidad", "autenticidad"],
  "ModoEjecucion": "automatico", "Dependencias": []
}
```

`Nivel`: `opcional|bajo|medio|alto`. `Tipo`: `refuerzo|requisito|recomendacion|medida`.
`Dimensiones`: `confidencialidad|integridad|trazabilidad|autenticidad|disponibilidad`.

### ISO 27001 — `iso27001_{year}_{provider}`

```json
{
  "Category": "A.5 Organizational controls",
  "Objetive_ID": "A.5.1", "Objetive_Name": "Policies for information security",
  "Check_Summary": "Summary of what is being checked"
}
```

Note: `Objetive_ID` / `Objetive_Name` use this exact (mis)spelling.

### MITRE ATT&CK — `mitre_attack_{provider}` (separate requirement model)

```json
{
  "Name": "Exploit Public-Facing Application", "Id": "T1190",
  "Tactics": ["Initial Access"], "SubTechniques": [],
  "Platforms": ["IaaS"], "Description": "...",
  "TechniqueURL": "https://attack.mitre.org/techniques/T1190/",
  "Checks": ["guardduty_is_enabled"],
  "Attributes": [
    {"AWSService": "Amazon GuardDuty", "Category": "Detect",
     "Value": "Minimal", "Comment": "..."}
  ]
}
```

`AzureService`/`GCPService` for the other providers. `Category`:
`Detect|Protect|Respond`. `Value`: `Minimal|Partial|Significant`.

### CCC — `ccc_{provider}`

```json
{
  "FamilyName": "Data", "FamilyDescription": "...",
  "Section": "CCC.Core.CN01 Encrypt Data for Transmission", "SubSection": "",
  "SubSectionObjective": "...",
  "Applicability": ["tlp-green", "tlp-amber", "tlp-red"],
  "Recommendation": "...",
  "SectionThreatMappings": [{"ReferenceId": "CCC", "Identifiers": ["CCC.Core.TH02"]}],
  "SectionGuidelineMappings": [{"ReferenceId": "NIST-CSF", "Identifiers": ["PR.DS-02"]}]
}
```

`Applicability` holds TLP tags (`tlp-clear|tlp-green|tlp-amber|tlp-red`).

### ASD Essential Eight — `asd_essential_eight_aws`

```json
{
  "Section": "Patch applications", "MaturityLevel": "ML1",
  "AssessmentStatus": "Automated", "CloudApplicability": "partial",
  "MitigatedThreats": ["..."], "Description": "...",
  "RationaleStatement": "...", "ImpactStatement": "...",
  "RemediationProcedure": "...", "AuditProcedure": "...",
  "AdditionalInformation": "...", "References": "..."
}
```

`MaturityLevel`: `ML1|ML2|ML3`. `CloudApplicability`: `full|partial|limited|non-applicable`.

### DISA STIG — `okta_idaas_stig_v1r2_okta`

```json
{
  "Section": "...", "Severity": "high", "RuleID": "...", "StigID": "...",
  "CCI": ["CCI-000015"], "CheckText": "...", "FixText": "..."
}
```

`Severity`: `high|medium|low` (maps to CAT I/II/III).

### Other registered shapes

- **AWS Well-Architected** (`aws_well_architected_framework_{pillar}_pillar_aws`):
  `Name`, `WellArchitectedQuestionId`, `WellArchitectedPracticeId`, `Section`,
  `SubSection`, `LevelOfRisk`, `AssessmentMethod`, `Description`,
  `ImplementationGuidanceUrl`.
- **KISA ISMS-P** (`kisa_isms_p_2023_{provider}`): `Domain`, `Subdomain`,
  `Section`, `AuditChecklist`, `RelatedRegulations`, `AuditEvidence`,
  `NonComplianceCases`.
- **C5** (`c5_{provider}`): `Section`, `SubSection`, `Type`, `AboutCriteria`,
  `ComplementaryCriteria`.
- **CSA CCM** (legacy shape; the shipped CSA CCM 4.0 is universal): `Section`,
  `CCMLite`, `IaaS`, `PaaS`, `SaaS`, `ScopeApplicability`.
- **Prowler ThreatScore** (`prowler_threatscore_{provider}`): `Title`,
  `Section`, `SubSection`, `AttributeDescription`, `AdditionalInformation`,
  `LevelOfRisk` (1–5), `Weight` (1/8/10/100/1000). Pillars: 1 IAM, 2 Attack
  Surface, 3 Logging and Monitoring, 4 Encryption. Available for aws,
  azure, gcp, kubernetes, m365, alibabacloud.
- **Generic (fallback)**: `ItemId`, `Section`, `SubSection`, `SubGroup`,
  `Service`, `Type`, `Comment` — all optional. Used by NIST, PCI, GDPR,
  HIPAA, SOC2, FedRAMP, CISA, FFIEC, RBI, NIS2, GxP, SecNumCloud, etc.

## Config Guardrails (`ConfigRequirements`)

Requirements backed by [configurable checks](https://docs.prowler.com/developer-guide/configurable-checks)
can be silently "satisfied" by a loosened `audit_config` (e.g. CIS demands
45-day unused credentials but the scan ran with `max_unused_access_keys_days: 120`).
Guardrails force such requirements to FAIL:

```json
"ConfigRequirements": [
  {"Check": "iam_user_accesskey_unused",
   "ConfigKey": "max_unused_access_keys_days", "Operator": "lte", "Value": 45}
]
```

- Operators: `lte`/`gte` (numeric thresholds), `eq` (toggles/exact — use JSON
  booleans, not 0/1), `in` (scalar in allowed set), `subset` (allowlists —
  widening breaks it), `superset` (denylists — removing an entry breaks it).
- `Value` must be the **strictest** setting the control text tolerates.
- `ConfigKey` must be spelled exactly as the check reads it; unknown keys are
  silently skipped (defaults assumed OK).
- Guardrails only tighten (PASS→FAIL), never relax.
- Universal files: lowercase `config_requirements` + mandatory `Provider` per
  constraint.
- Tests: `tests/lib/check/compliance_config_eval_test.py`,
  `compliance_config_constraint_model_test.py`,
  `compliance_config_requirements_data_test.py`, plus per-output tests under
  `tests/lib/outputs/compliance/`.

---

## Workflow A: Sync a Framework With an Upstream Catalog

Use when the framework is maintained upstream (CIS Benchmarks, FINOS CCC, CSA
CCM, NIST, ENS, etc.) and Prowler needs to catch up.

### Step 1 — Cache the upstream source

Download every upstream file to a local cache so iterations don't hit the
network. For FINOS CCC:

```bash
mkdir -p /tmp/ccc_upstream
catalogs="core/ccc storage/object management/auditlog management/logging ..."
for p in $catalogs; do
  safe=$(echo "$p" | tr '/' '_')
  gh api "repos/finos/common-cloud-controls/contents/catalogs/$p/controls.yaml" \
    -H "Accept: application/vnd.github.raw" > "/tmp/ccc_upstream/${safe}.yaml"
done
```

### Step 2 — Run the generic sync runner against a framework config

The sync tooling is three layers, so adding a framework only takes a YAML
config (plus a parser module for an unfamiliar upstream format):

```text
skills/prowler-compliance/assets/
├── sync_framework.py          # generic runner — works for any framework
├── configs/ccc.yaml           # per-framework config (canonical example)
└── parsers/finos_ccc.py       # parser module for FINOS CCC YAML
```

```bash
python skills/prowler-compliance/assets/sync_framework.py \
       skills/prowler-compliance/assets/configs/ccc.yaml
```

The runner loads the config, dynamically imports `parser.module`, calls
`parse_upstream(config) -> list[dict]`, then applies generic post-processing
(id-uniqueness safety net, `FamilyName` normalization, legacy check-mapping
preservation with config-driven fallback keys) and writes the provider JSONs
with Pydantic post-validation.

**To add a new framework sync**:

1. Write `assets/configs/{framework}.yaml` (see `ccc.yaml`). Required sections:
   - `framework` — `name`, `display_name`, `version` (**never empty** — the
     runner refuses to start, because empty Version breaks the
     `get_check_compliance()` key), `description_template`.
   - `providers` — list of `{key, display}` pairs.
   - `output.path_template` — e.g.
     `"prowler/compliance/{provider}/cis_{version}_{provider}.json"`.
   - `upstream.dir` — local cache (Step 1).
   - `parser.module` — module under `parsers/`; the rest of `parser.` is
     passed through opaque.
   - `post_processing.check_preservation.primary_key` (almost always `Id`) and
     `fallback_keys` — lists of `Attributes[0]` field names composed into
     tuples for recovering mappings when ids change. CCC:
     `- [Section, Applicability]`; CIS: `- [Section, Profile]`; NIST:
     `- [ItemId]`. List-valued fields are frozen to `frozenset` automatically.
   - `post_processing.family_name_normalization` (optional) — raw → canonical
     map; the UI groups by the exact attribute value, so upstream variants
     otherwise become separate tree branches.
2. Reuse an existing parser or write `parsers/{name}.py` implementing
   `parse_upstream(config) -> list[dict]` returning Prowler-format
   requirements with **guaranteed-unique ids**. The runner raises on
   duplicates — it never silently renumbers, because mutating a canonical
   upstream id (CIS `1.1.1`, NIST `AC-2(1)`) would be catastrophic. The parser
   owns all upstream quirks: foreign-prefix rewriting, genuine collision
   renumbering, multi-shape handling.

**Gotchas the runner already handles** (from the FINOS CCC v2025.10 sync):

- **Multiple upstream YAML shapes.** Most FINOS CCC catalogs use
  `control-families: [...]` but `storage/object` uses top-level
  `controls: [...]`. A single-shape parser silently drops entire catalogs —
  this exact bug dropped ObjStor for a full iteration. Test with one file of
  each shape.
- **Whitespace collapse.** Upstream `|` block scalars keep newlines; Prowler
  stores single-line. Collapse with `" ".join(value.split())`.
- **Foreign-prefix id rewriting.** Upstream aliases requirements across
  catalogs keeping the original prefix (`CCC.AuditLog.CN08.AR01` nested under
  `CCC.Logging.CN03`) — rewrite to fit the parent (`CCC.Logging.CN03.AR01`).
- **Genuine upstream collisions.** Two different requirements sharing one id
  (upstream typo): renumber the second to the next free number; check-mapping
  preservation recovers by the fallback keys.
- **Populate `Version`** — fail-fast beats the silent broken-key bug.

### Step 3 — Validate before committing

Run the full Validation section below (universal loader + check existence +
CLI smoke + pytest).

### Step 4 — Add an attribute model if needed

Only if the framework has fields beyond
`Generic_Compliance_Requirement_Attribute` and must stay legacy. Add the class
to `compliance_models.py` and register it in the
`Compliance_Requirement.Attributes` Union **before Generic** (Generic stays
last). For new frameworks, prefer universal `attributes_metadata` instead.

---

## Workflow B: Audit Check Mappings as a Cloud Auditor

Use when the user asks to review existing mappings. This is the
highest-value compliance task — it surfaces padded mappings with zero actual
coverage and missing mappings for legitimate coverage.

### The golden rule

> A Prowler check's title/risk MUST **literally describe what the requirement
> text says**. "Related" is not enough. If no check actually addresses the
> requirement, leave the checks list empty (MANUAL) — **honest MANUAL is worth
> more than padded coverage**.

### Audit process

1. **Build a per-provider check inventory** — `assets/build_inventory.py`
   (writes `/tmp/checks_{provider}.json` for every provider discovered under
   `prowler/providers/`).
2. **Query it** — `assets/query_checks.py` (run from the repository root):

   ```bash
   python skills/prowler-compliance/assets/query_checks.py aws encryption transit  # keyword AND-search
   python skills/prowler-compliance/assets/query_checks.py aws --service iam       # all iam checks
   python skills/prowler-compliance/assets/query_checks.py aws --id kms_cmk_rotation_enabled
   ```

3. **Dump a framework section with current mappings** — `assets/dump_section.py`:

   ```bash
   python skills/prowler-compliance/assets/dump_section.py ccc "CCC.Core."
   python skills/prowler-compliance/assets/dump_section.py cis_5.0_aws "1."
   ```

4. **Encode explicit REPLACE decisions** — `assets/audit_framework_template.py`:

   ```python
   DECISIONS = {}
   DECISIONS["CCC.Core.CN01.AR01"] = {
       "aws": ["cloudfront_distributions_https_enabled", ...],
       "azure": ["storage_secure_transfer_required_is_enabled", ...],
       "gcp": ["cloudsql_instance_ssl_connections"],
       # Missing provider key = leave the legacy mapping untouched
   }
   # Empty list = EXPLICITLY MANUAL (overwrites legacy)
   DECISIONS["CCC.Core.CN01.AR07"] = {"aws": [], "azure": [], "gcp": []}
   ```

   **REPLACE, not PATCH.** Full lists make the audit reproducible and surface
   hidden assumptions in the legacy data.
5. **Pre-validate** every check id against the inventory; the script MUST
   abort with stderr listing typos (real audits caught
   `storage_secure_transfer_required_enabled` →
   `storage_secure_transfer_required_is_enabled`,
   `sqlserver_minimum_tls_version_12` →
   `sqlserver_recommended_minimal_tls_version`, and several checks that
   simply don't exist).
6. **Apply + validate + test**:

   ```bash
   python /path/to/audit_script.py
   uv run pytest -n auto tests/lib/outputs/compliance/ tests/lib/check/ -q
   ```

For the curated mapping table (requirement text → AWS/Azure/GCP checks) and
the list of controls Prowler genuinely cannot verify, see
[references/check-mapping-reference.md](references/check-mapping-reference.md).

---

## Workflow C: Add a New Universal Framework

1. Author `prowler/compliance/{framework}_{version}.json` following the
   Universal Schema Reference above (use `dora_2022_2554.json` or
   `csa_ccm_4.0.json` as template).
2. Declare every attribute in `attributes_metadata` (with `required`/`enum`
   where possible — that's your load-time validation) and a
   `outputs.table_config.group_by`.
3. Map checks per provider; add `config_requirements` (with `Provider`) for
   configurable checks; leave empty lists for manual requirements — **include
   every requirement of the source catalog** (coverage percentages depend on
   the full denominator).
4. Validate (section below). No Python registration of any kind is needed for
   CLI table/CSV/OCSF.
5. Optional first-class UI: mapper in `ui/lib/compliance/{framework}.tsx`,
   registration in `getComplianceMappers()` under the JSON's `framework` value,
   detail panel, `*AttributesMetadata` type, and icon (ordered keyword!). Until
   then the generic mapper renders it.
6. Optional API extras: CSV exporter entry in `COMPLIANCE_CLASS_MAP`; PDF
   generator + `FRAMEWORK_REGISTRY` entry if a PDF is required.
7. Tests: extend `tests/lib/check/universal_compliance_models_test.py` with a
   case loading the new JSON. The parametrized `test_loads_as_universal`
   already picks the file up automatically.
8. Changelog fragment `prowler/changelog.d/<slug>.added.md` + user-guide
   tutorial under `docs/user-guide/compliance/tutorials/` for high-profile
   frameworks.

## Workflow D: Add a New Legacy Output Formatter

Only for new members of an existing legacy family. Follow the `c5/` or `ccc/`
layout exactly:

1. `mkdir prowler/lib/outputs/compliance/{framework}` with `__init__.py`.
2. `{framework}.py` — copy `c5/c5.py`, change function name + framework
   string; the diff should be just those lines. No docstring (legacy style).
3. `models.py` — one Pydantic CSV row model per provider. Column sets differ
   per provider (`AccountId`/`Region` vs `SubscriptionId`/`Location` vs
   `ProjectId`/`Location`); per-provider files are the convention — don't
   collapse them into a parameterized class, reviewers will reject it.
4. `{framework}_{provider}.py` — `{Framework}_{Provider}(ComplianceOutput)`
   with `transform()`; this file may import `Finding`.
5. Register:
   - `compliance.py` → `display_compliance_table()` `elif` branch (+ top import).
   - `prowler/__main__.py` → per-provider `elif compliance_name.startswith(...)`
     branches instantiating the writer classes.
   - `api/src/backend/tasks/jobs/export.py` → `COMPLIANCE_CLASS_MAP` entries
     (`startswith` for families, exact match only for true singletons).
6. Tests under `tests/lib/outputs/compliance/{framework}/` + fixtures in
   `tests/lib/outputs/compliance/fixtures.py` (1 evaluated + 1 manual
   requirement to exercise both `transform()` paths).

**Circular import warning**: the table file must not import `Finding` directly
or transitively (cycle: `compliance.compliance` → table → `ComplianceOutput` →
`Finding` → `get_check_compliance` → `compliance.compliance`). Keep it bare;
use `TYPE_CHECKING`/function-local imports where both are genuinely needed.

---

## Validation (run before every commit)

1. **Schema load (both formats)**:

   ```python
   from prowler.lib.check.compliance_models import (
       load_compliance_framework_universal,
       get_bulk_compliance_frameworks_universal,
   )
   fw = load_compliance_framework_universal("prowler/compliance/<file>.json")
   assert fw is not None, "check logs for the ValidationError"
   print(fw.framework, len(fw.requirements), fw.get_providers())
   assert "<file_basename>" in get_bulk_compliance_frameworks_universal("aws")
   ```

   Remember: the universal loader is lenient (skips broken files with a log
   line) — an `assert fw is not None` is mandatory, a green scan is not proof.

2. **Check existence** — no loader validates this; a stale id is silent dead
   weight:

   ```python
   import json
   from pathlib import Path
   for prov in ["aws", "azure", "gcp"]:
       real = {p.stem.replace(".metadata", "")
               for p in Path(f"prowler/providers/{prov}/services").rglob("*.metadata.json")}
       data = json.load(open(f"prowler/compliance/{prov}/<file>.json"))
       refs = {c for r in data["Requirements"] for c in r["Checks"]}
       missing = refs - real
       assert not missing, f"{prov} missing: {missing}"
   ```

   (For universal files use `r.get("checks", {}).get(prov, [])` instead —
   requirements may legitimately omit a provider key.)

3. **CLI smoke test**:

   ```bash
   uv run python prowler-cli.py <provider> --list-compliance          # appears?
   uv run python prowler-cli.py <provider> --compliance <key> --log-level ERROR
   ```

   Verify the CSV under `output/compliance/`, the summary table sections, and
   the findings roll-up.

4. **Tests**:

   ```bash
   uv run pytest -n auto tests/lib/check/universal_compliance_models_test.py \
     tests/lib/outputs/compliance/
   ```

   `test_loads_as_universal` is parametrized over **every** JSON in
   `prowler/compliance/` (top-level + subdirectories) — a malformed file fails
   CI here even if you never wrote a dedicated test.

5. **What CI/pre-commit do and don't cover**: pre-commit only guarantees
   well-formed/pretty JSON (`check-json`, `pretty-format-json`) — no semantic
   validation. The workflow `.github/workflows/pr-check-compliance-mapping.yml`
   flags PRs adding new checks without mapping them to any framework (label
   `needs-compliance-review`; skip with label `no-compliance-check`). Semantic
   validation happens in the pytest suite above and manually via
   `skills/prowler-compliance-review/assets/validate_compliance.py` (note:
   that validator assumes the **legacy** schema).

6. **Prowler Local Server**: `docker compose up` and confirm the compliance
   page renders requirements, sections and widgets.

---

## Conventions and Hard-Won Gotchas

1. **Universal first.** A new framework that starts as legacy needs 3 output
   files + 3 registrations; the same framework as universal needs zero. Only
   extend legacy families.
2. **`Generic_Compliance_Requirement_Attribute` stays LAST** in the legacy
   Attributes Union — Pydantic v1 tries members in order; Generic first
   silently swallows every specific shape.
3. **Pydantic v1 everywhere in `compliance_models.py`**
   (`from pydantic.v1 import ...`). Don't mix in v2.
4. **`get_check_compliance()` lives in
   `prowler/lib/outputs/compliance/compliance_check.py`** and keys the dict
   `f"{Framework}-{Version}"` only when Version is non-empty. Never ship
   `Version: ""` — the key silently degrades to `"{Framework}"` and breaks
   filters, tests and `--compliance`. For legacy files the filename version
   substring must match `Version` (the CLI reads
   `compliance_framework.split("_")[1]`).
5. **`Compliance.get_bulk()` does not see top-level universal files** — only
   `get_bulk_compliance_frameworks_universal()` does. Wire new code paths
   against the universal loader.
6. **Loader leniency differs**: legacy loader exits the process on a broken
   JSON; universal loader logs and skips. A missing framework after your edit
   usually means the universal loader dropped it — check the logs.
7. **Circular import protection**: legacy table dispatcher files must not
   import `Finding` (directly or transitively). Use `TYPE_CHECKING` or
   function-local imports when a module needs both sides (that's how the
   universal formatter does it).
8. **Per-provider formatter files are the legacy convention** — but know the
   exceptions before flagging them (iso27001 has no table file,
   aws_well_architected has no per-provider files, cisa_scuba is
   googleworkspace-only). CSV model field names are public API.
9. **CSV output**: `;` delimiter, UPPERCASE headers. OCSF compliance output is
   always generated for universal frameworks regardless of `--output-formats`.
10. **`COMPLIANCE_CLASS_MAP` mixes predicate styles**: `startswith` for
    multi-version families, exact `==` for singletons. When in doubt use
    `startswith` — exact match blocked versioned CCC variants until 2026.
11. **UI grouping is per-mapper, always on `attributes[0]`**: generic/cis →
    `Section`/`SubSection`, iso → `Category`, ccc → `FamilyName`. Inconsistent
    values (or empty Section) create orphan/duplicate tree branches — normalize
    before shipping.
12. **UI has a generic fallback** — an unregistered framework still renders.
    A dedicated mapper/panel/icon is an upgrade, not a prerequisite.
13. **Icon registration is ordered substring matching** in
    `IconCompliance.tsx` — specific keywords before generic (`nist` before
    `nis2`, `cisa` before `cis`, `aws` last).
14. **API PDF pipeline is not `PDFConfig`-driven yet** — it has its own
    `FRAMEWORK_REGISTRY` (5 frameworks). Don't assume adding `pdf_config` to a
    JSON produces a PDF in Prowler App.
15. **Pre-validate every check id** against the per-provider inventory before
    writing JSON. No loader will catch a typo; the requirement just never
    matches a finding.
16. **REPLACE beats PATCH** for audit decisions — full explicit lists are
    reproducible and surface legacy assumptions.
17. **When no check applies, MANUAL is correct.** Don't pad mappings with
    tangential checks; compliance reports must stay actionable.
18. **Include every requirement of the source catalog**, automated or not —
    compliance percentages use the full requirement count as denominator.
19. **Provider coverage is asymmetric** (AWS dense; Azure/GCP thinner; new
    providers minimal). Accept it — don't force parity Prowler can't verify.
20. **Guardrail authoring**: strictest tolerated `Value`, exact `ConfigKey`
    spelling, `Provider` mandatory in universal files, booleans as JSON
    booleans. Malformed constraints are treated as satisfied — validate with
    the config tests, don't trust silence.

---

## Useful One-Liners

```bash
# Find duplicate requirement IDs (legacy | universal)
jq -r '.Requirements[].Id' file.json | sort | uniq -d
jq -r '.requirements[].id' file.json | sort | uniq -d

# Count manual requirements (legacy | universal, per provider)
jq '[.Requirements[] | select((.Checks | length) == 0)] | length' file.json
jq '[.requirements[] | select((.checks.aws // [] | length) == 0)] | length' file.json

# List unique check references (legacy | universal)
jq -r '.Requirements[].Checks[]' file.json | sort -u
jq -r '.requirements[].checks[]? | .[]' file.json | sort -u

# Providers covered by a universal framework
jq '[.requirements[].checks | keys[]] | unique' file.json

# Spot inconsistent grouping values (UI tree branches)
jq '[.Requirements[].Attributes[0].Section] | unique' file.json
jq '[.Requirements[].Attributes[0].FamilyName] | unique' file.json

# Requirements with config guardrails (empty arrays are truthy in jq — check length)
jq '[.Requirements[] | select((.ConfigRequirements // []) | length > 0)] | length' file.json

# Diff requirement ids between two versions
diff <(jq -r '.Requirements[].Id' a.json | sort) <(jq -r '.Requirements[].Id' b.json | sort)

# Where is a check mapped across all frameworks?
grep -rl "my_check_name" prowler/compliance/

# Does a check exist?
find prowler/providers/aws/services -name "{check_id}.metadata.json"

# Validate one file with the universal loader
python -c "from prowler.lib.check.compliance_models import load_compliance_framework_universal as l; fw=l('prowler/compliance/aws/cis_7.0_aws.json'); print(fw.framework, len(fw.requirements))"
```

## Commands

```bash
prowler {provider} --list-compliance
prowler {provider} --compliance cis_7.0_aws
prowler aws --compliance cis_7.0_aws pci_4.0_aws
prowler aws --compliance dora_2022_2554            # universal key = file basename
prowler aws --list-compliance-requirements cis_7.0_aws
prowler aws --compliance cis_7.0_aws -M csv json html
```

## Code References

### Layer 1 — SDK / Core

- `prowler/lib/check/compliance_models.py` — legacy + universal model trees,
  `Compliance_Requirement_ConfigConstraint`, all loaders and the
  legacy→universal adapter
- `prowler/lib/check/compliance.py` — `update_checks_metadata_with_compliance`
- `prowler/lib/check/compliance_config_eval.py` — guardrail evaluation
  (shared with the API)
- `prowler/lib/outputs/compliance/compliance_check.py` — `get_check_compliance`
- `prowler/lib/check/utils.py` — `list_compliance_modules`

### Layer 2 — JSON Catalogs

- `prowler/compliance/*.json` — universal, multi-provider (auto-discovered)
- `prowler/compliance/{provider}/` — legacy, per-provider (auto-discovered)

### Layer 3 — Output Formatters

- `prowler/lib/outputs/compliance/universal/` — `universal_table.py`,
  `universal_output.py`, `ocsf_compliance.py`
- `prowler/lib/outputs/compliance/{framework}/` — legacy per-framework packages
- `prowler/lib/outputs/compliance/compliance.py` —
  `process_universal_compliance_frameworks`, `display_compliance_table`
- `prowler/lib/outputs/compliance/compliance_output.py` — `ComplianceOutput`
  base + CSV writer
- `prowler/__main__.py` — universal processing + per-provider legacy writer
  branches

### Layer 4 — API / UI

- `api/src/backend/api/compliance.py` — `LazyComplianceTemplate`,
  `LazyChecksMapping`, cache warm-up
- `api/src/backend/tasks/jobs/export.py` — `COMPLIANCE_CLASS_MAP`
- `api/src/backend/tasks/jobs/scan.py` — `create_compliance_requirements`
  (overview ingestion)
- `api/src/backend/tasks/jobs/reports/` — PDF generators + `FRAMEWORK_REGISTRY`
- `ui/lib/compliance/compliance-mapper.ts` — mapper routing + generic fallback
- `ui/lib/compliance/{framework}.tsx` — per-framework mappers
- `ui/components/compliance/compliance-custom-details/` — detail panels
- `ui/types/compliance.ts` — attribute metadata types
- `ui/components/icons/compliance/` + `IconCompliance.tsx` — icons (ordered)

### Tests

- `tests/lib/check/universal_compliance_models_test.py` — includes the
  parametrized `test_loads_as_universal` over every shipped JSON
- `tests/lib/check/compliance_check_test.py`,
  `compliance_config_eval_test.py`, `compliance_config_constraint_model_test.py`,
  `compliance_config_requirements_data_test.py`, `mitre_config_requirements_test.py`
- `tests/lib/outputs/compliance/` — per-framework + universal + dispatcher +
  config-status coverage tests; shared `fixtures.py`

## Resources

- **Docs (source of truth for contributors)**:
  `docs/developer-guide/security-compliance-framework.mdx` (both schemas,
  guardrails, validation, PR process),
  `docs/user-guide/compliance/tutorials/compliance.mdx`,
  `docs/user-guide/compliance/tutorials/cross-provider-compliance.mdx`
- **Repo tooling** (`util/compliance/`): CSV→JSON generators
  (`generate_json_from_csv/`), `ccc/from_yaml_to_json.py`,
  `compliance_mapper/`, `threatscore/`
- **Skill assets** ([assets/](assets/)):
  - `sync_framework.py` + `configs/ccc.yaml` + `parsers/finos_ccc.py` —
    config-driven upstream sync (Workflow A)
  - `build_inventory.py`, `query_checks.py`, `dump_section.py`,
    `audit_framework_template.py` — audit tooling (Workflow B)
  - Legacy JSON templates: `cis_framework.json`, `ens_framework.json`,
    `iso27001_framework.json`, `mitre_attack_framework.json`,
    `prowler_threatscore_framework.json`, `generic_framework.json`
- **References**:
  [references/compliance-docs.md](references/compliance-docs.md) — model/loader
  quick reference;
  [references/check-mapping-reference.md](references/check-mapping-reference.md)
  — curated requirement-text → checks mapping table + honest-MANUAL list
- **Sister skill**:
  [prowler-compliance-review](../prowler-compliance-review/SKILL.md) — PR
  review checklist + `validate_compliance.py` (legacy-schema validator)
- After editing this skill's frontmatter, run
  `./skills/skill-sync/assets/sync.sh` to regenerate the AGENTS.md auto-invoke
  tables.
