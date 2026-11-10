# Compliance Architecture and Code Reference

Four layers. Most bugs come from one layer disagreeing with another.

## Layer 1: SDK models and loaders (`prowler/lib/check/`)

| Symbol | File | Notes |
|---|---|---|
| `Compliance`, `Compliance_Requirement`, `Mitre_Requirement`, `*_Requirement_Attribute` | `compliance_models.py` | Legacy tree |
| `ComplianceFramework`, `UniversalComplianceRequirement`, `AttributeMetadata`, `OutputsConfig`, `TableConfig`, `PDFConfig` | `compliance_models.py` | Universal tree |
| `Compliance_Requirement_ConfigConstraint` | `compliance_models.py` | Guardrail model, shared by both trees |
| `Compliance.get_bulk(provider)` | `compliance_models.py` | Legacy loader |
| `get_bulk_compliance_frameworks_universal(provider)` | `compliance_models.py` | Universal loader |
| `load_compliance_framework(path, fatal=True)` | `compliance_models.py` | Legacy single-file load |
| `load_compliance_framework_universal(path)` | `compliance_models.py` | Universal or adapted-legacy load; returns `None` on error |
| `adapt_legacy_to_universal()` | `compliance_models.py` | Flattens `Attributes[0]`, wraps `Checks` as `{provider: [...]}`, infers `attributes_metadata` |
| `update_checks_metadata_with_compliance()` | `compliance.py` (only function there) | Attaches legacy frameworks to `CheckMetadata.Compliance` |
| `evaluate_config_constraints()` etc. | `compliance_config_eval.py` | Guardrail evaluation (CLI + API) |
| `get_check_compliance()` | `prowler/lib/outputs/compliance/compliance_check.py` | Per-finding `{"{Framework}-{Version}": [ids]}` |
| `list_compliance_modules()` | `utils.py` | `walk_packages` over `prowler.compliance` |
| `get_available_compliance_frameworks()` | `prowler/config/config.py` | Feeds `--compliance` choices (built-in + entry points) |

### Loader behavior

| | `Compliance.get_bulk(provider)` | `get_bulk_compliance_frameworks_universal(provider)` |
|---|---|---|
| Built-in dirs | `prowler/compliance/{provider}/` only | Every `prowler/compliance/{p}/` + top-level `prowler/compliance/*.json` |
| Included when | File is in the provider dir | `fw.provider` matches, or any requirement has a `checks` key for the provider |
| External | `prowler.compliance` entry points whose name equals the provider (legacy JSON) | `prowler.compliance.universal` entry points (`UNIVERSAL_COMPLIANCE_ENTRY_POINT_GROUP`) |
| Invalid built-in file | `logger.critical` + `sys.exit(1)` | Logged, skipped |
| Invalid external file | Warning, skipped (`fatal=False`) | Logged, skipped |
| Name collision | Built-in wins | Built-in wins |

Framework key = JSON basename without `.json` (also the `--compliance` value).

### External compliance plug-ins (entry points)

A third-party package can ship frameworks without touching Prowler:

```toml
# Legacy per-provider JSONs: the entry point NAME must be the provider key
[project.entry-points."prowler.compliance"]
aws = "my_pkg.compliance.aws"      # package/module whose directory holds *.json

# Universal multi-provider JSONs: the name is free
[project.entry-points."prowler.compliance.universal"]
my_frameworks = "my_pkg.universal"
```

The loader resolves the module directory (`module.__path__[0]` or `dirname(module.__file__)`) and reads
every `*.json` in it. Universal directories are deduplicated by resolved path; a package that fails to
import is logged and skipped. Loader tests: `tests/lib/check/universal_compliance_models_test.py`.

## Layer 2: JSON catalogs (`prowler/compliance/`)

Do not trust hardcoded counts; regenerate:

```bash
ls prowler/compliance/*.json                                   # universal
for d in prowler/compliance/*/; do printf "%s: %s\n" "$(basename "$d")" "$(ls "$d"*.json 2>/dev/null | wc -l)"; done
jq -r '[.requirements[].checks | keys[]] | unique | join(",")' prowler/compliance/<file>.json
```

At 5.48 the universal files are `cis_controls_8.1`, `cmmc_2.0`, `csa_ccm_4.0`, `cyber_essentials_3.3`,
`dora_2022_2554`, `fedramp_20x_frr_class_c_2026` and `fedramp_20x_ksi_2026`. Some provider directories have
only `__init__.py` (cloudflare, iac, linode, llm, mongodbatlas, openstack, stackit).

## Layer 3: Output formatters (`prowler/lib/outputs/compliance/`)

### Universal (data driven)

- `universal/universal_table.py` `get_universal_table()`: CLI table from `table_config`.
- `universal/universal_output.py` `UniversalComplianceOutput`: CSV, columns built from `attributes_metadata`.
- `universal/ocsf_compliance.py` `OCSFComplianceOutput`: OCSF JSON, always written for universal frameworks.
- `compliance.py` `process_universal_compliance_frameworks()`: runs first, only for frameworks with
  `outputs.table_config`, and returns the processed names so the legacy loop skips them.
- Universal-only frameworks are not passed to `update_checks_metadata_with_compliance()`, so they do not
  appear in the per-finding compliance field of the regular finding outputs; they get their own
  `output/compliance/<prefix>_<name>.csv` and `.ocsf.json`.

### Legacy (per framework package)

```text
{framework}/
├── __init__.py
├── {framework}.py            # get_{framework}_table(); must not import Finding (circular import)
├── {framework}_{provider}.py # {Provider}{Framework}(ComplianceOutput).transform(); may import Finding
└── models.py                 # one CSV row model per provider; field names are public API
```

Packages: `asd_essential_eight`, `aws_well_architected`, `c5`, `ccc`, `cis`, `cisa_scuba`, `ens`,
`generic`, `iso27001`, `kisa_ismsp`, `mitre_attack`, `okta_idaas_stig`, `prowler_threatscore`. Known
deviations: `iso27001/` and `cisa_scuba/` have no table file (generic table), `aws_well_architected/` has a
single writer module, `cisa_scuba` is googleworkspace-only.

`display_compliance_table()` dispatch order: universal (`table_config`) → `cis_` → `ens_` → `mitre_attack`
→ `kisa` → `prowler_threatscore_` → `c5_` → `ccc_` → `"asd_essential_eight" in name` → `okta_idaas_stig` →
`provider.display_compliance_table()` (external providers; may raise `NotImplementedError`) →
`get_generic_compliance_table()`.

CSV writer base: `ComplianceOutput` in `compliance_output.py` (`;` delimiter, UPPERCASE headers).

`prowler/__main__.py` has explicit legacy writer branches only for aws, azure, gcp, kubernetes, m365, nhn,
github, googleworkspace, oraclecloud, alibabacloud and okta. Any other provider goes through
`global_provider.generate_compliance_output()` and falls back to `GenericCompliance` on
`NotImplementedError`.

### Local dashboard (`dashboard/compliance/`)

`dashboard/pages/compliance.py` imports `dashboard.compliance.<key with dots replaced by underscores>` and
falls back to `dashboard/compliance/generic.py` when that module does not exist. A dedicated dashboard file
is optional.

## Layer 4: API and UI

| Concern | Location | Notes |
|---|---|---|
| Lazy framework caches | `api/src/backend/api/compliance.py` | `LazyComplianceTemplate`, `LazyChecksMapping`, warm-up under Gunicorn; built on the universal loader |
| Overview ingestion | `api/src/backend/tasks/jobs/scan.py` `create_compliance_requirements()` | |
| Compliance CSV export | `api/src/backend/tasks/tasks.py` + `tasks/jobs/export.py` `COMPLIANCE_CLASS_MAP` | `COMPLIANCE_CLASS_MAP` serves legacy frameworks only (`GenericCompliance` fallback). Universal-only frameworks are exported automatically via `process_universal_compliance_frameworks()` |
| PDF reports | `api/src/backend/tasks/jobs/reports/` + `tasks/jobs/report.py` | Hardcoded `FRAMEWORK_REGISTRY` (`prowler_threatscore`, `ens`, `nis2`, `csa_ccm`, `cis`); `pdf_config` is not read |
| UI mapper routing | `ui/lib/compliance/compliance-mapper.ts` `getComplianceMapper()` | Keyed by JSON `framework`; unknown values use the generic mapper |
| UI mappers / detail panels | `ui/lib/compliance/*.tsx`, `ui/components/compliance/compliance-custom-details/` | |
| UI types | `ui/types/compliance.ts` | `*AttributesMetadata` interfaces |
| UI icons | `ui/components/icons/compliance/IconCompliance.tsx` `COMPLIANCE_LOGOS` | Ordered substring match: `essentials` before `essential`, `cisa` before `cis`, `nist` before `nis2` |

`COMPLIANCE_CLASS_MAP` predicates mix `startswith` (families) and exact `==` (`mitre_attack_*`,
`prowler_threatscore_*`, `asd_essential_eight_aws`, and `c5_azure`/`c5_gcp` while aws uses
`startswith("c5_")`). Prefer `startswith` for anything that can get versions.

## CLI pipeline

```text
prowler aws --compliance cis_7.0_aws
  Compliance.get_bulk("aws")                       # legacy only
  update_checks_metadata_with_compliance()         # legacy only -> CheckMetadata.Compliance
  get_bulk_compliance_frameworks_universal("aws")  # universal + adapted legacy
  execute checks -> findings (get_check_compliance per finding)
  process_universal_compliance_frameworks()        # universal CSV + OCSF, removed from the set
  per-provider legacy writer branches in __main__  # legacy CSV
  display_compliance_table()                       # universal table first, then legacy dispatch
```

`--list-compliance` and `--list-compliance-requirements` print the union of both bulks.

## Repo tooling (`util/compliance/`)

| Path | Purpose |
|---|---|
| `generate_json_from_csv/` | CSV→JSON generators (CIS 1.5, CIS 2.0 GCP, CIS 1.0 GitHub, CIS 4.0 M365, ENS, ThreatScore) |
| `ccc/from_yaml_to_json.py` | FINOS CCC YAML→JSON |
| `compliance_mapper/` | Compliance mapper |
| `threatscore/get_prowler_threatscore_from_generic_output.py` | ThreatScore from generic output |

## Useful one-liners

```bash
jq -r '.Requirements[].Id' f.json | sort | uniq -d                     # duplicate ids (legacy)
jq -r '.requirements[].id' f.json | sort | uniq -d                     # duplicate ids (universal)
jq '[.Requirements[] | select((.Checks|length)==0)] | length' f.json   # manual reqs (legacy)
jq '[.requirements[] | select((.checks.aws // [] | length)==0)] | length' f.json
jq '[.Requirements[].Attributes[0].Section] | unique' f.json          # grouping drift (UI branches)
diff <(jq -r '.Requirements[].Id' a.json | sort) <(jq -r '.Requirements[].Id' b.json | sort)
grep -rl "my_check_name" prowler/compliance/                           # where a check is mapped
```
