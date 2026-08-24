# Compliance Framework Quick Reference

## Code References

| File | Purpose |
|------|---------|
| `prowler/lib/check/compliance_models.py` | Legacy + universal Pydantic (v1) model trees, config-constraint model, loaders, legacy→universal adapter |
| `prowler/lib/check/compliance.py` | `update_checks_metadata_with_compliance()` (only) |
| `prowler/lib/check/compliance_config_eval.py` | Shared `ConfigRequirements` guardrail evaluation (SDK outputs + API) |
| `prowler/lib/outputs/compliance/compliance_check.py` | `get_check_compliance()` — per-finding `{Framework}-{Version}` → requirement ids |
| `prowler/lib/check/utils.py` | `list_compliance_modules()` |
| `prowler/lib/outputs/compliance/` | Output formatters (legacy per-framework + `universal/`) |
| `prowler/compliance/*.json` | Universal multi-provider framework definitions |
| `prowler/compliance/{provider}/` | Legacy per-provider framework definitions |

## Attribute Model Classes (legacy schema)

Registered in the `Compliance_Requirement.Attributes` Union, in this order
(order is load-bearing; Generic must stay last):

| Framework family | Model Class |
|-----------|-------------|
| ASD Essential Eight | `ASDEssentialEight_Requirement_Attribute` |
| CIS | `CIS_Requirement_Attribute` |
| ENS | `ENS_Requirement_Attribute` |
| ISO 27001 | `ISO27001_2013_Requirement_Attribute` |
| AWS Well-Architected | `AWS_Well_Architected_Requirement_Attribute` |
| KISA ISMS-P | `KISA_ISMSP_Requirement_Attribute` |
| Prowler ThreatScore | `Prowler_ThreatScore_Requirement_Attribute` |
| CCC | `CCC_Requirement_Attribute` |
| C5 Germany | `C5Germany_Requirement_Attribute` |
| CSA CCM (legacy shape) | `CSA_CCM_Requirement_Attribute` |
| DISA STIG (Okta IDaaS) | `STIG_Requirement_Attribute` |
| Generic/Fallback (NIST, PCI, GDPR, HIPAA, SOC2, FedRAMP, ...) | `Generic_Compliance_Requirement_Attribute` |

MITRE ATT&CK uses the separate `Mitre_Requirement` model with per-provider
`Mitre_Requirement_Attribute_{AWS,Azure,GCP}` attribute classes.

`Compliance_Requirement_ConfigConstraint` models each `ConfigRequirements` /
`config_requirements` entry (`Check`, `ConfigKey`, `Operator`, `Value`,
optional `Provider`) with load-time operator/value type validation.

## Universal Schema Models

| Model | Purpose |
|-------|---------|
| `ComplianceFramework` | Top-level container (`framework`, `name`, `version`, `requirements`, `attributes_metadata`, `outputs`); validates attributes against metadata at load |
| `UniversalComplianceRequirement` | Flat `attributes: dict`, `checks: dict[provider, list]`, `config_requirements`, MITRE extras |
| `AttributeMetadata` | Per-attribute schema descriptor (key/label/type/enum/required/`enum_display`/`enum_order`/`output_formats`) |
| `OutputsConfig` → `TableConfig` | CLI table rendering (`group_by`, `split_by`, `scoring`, `labels`) — consumed by `universal_table.py` |
| `OutputsConfig` → `PDFConfig` (+ `ChartConfig`, `ScoringFormula`, `I18nLabels`, ...) | Declarative PDF config — modeled but **not yet consumed** by the API PDF pipeline (it uses its own `FRAMEWORK_REGISTRY`) |

## How Frameworks Are Loaded

Two entry points — they see different files:

1. **Legacy**: `Compliance.get_bulk(provider)` scans only
   `prowler/compliance/{provider}/` (exact provider-segment match) plus
   external JSONs from the `prowler.compliance` entry-point group. Invalid
   built-in file → `logger.critical` + `sys.exit(1)`
   (`load_compliance_framework`, `fatal=True`).
2. **Universal**: `get_bulk_compliance_frameworks_universal(provider)` scans
   the top-level `prowler/compliance/` **and** every provider subdirectory,
   plus the `prowler.compliance.universal` entry-point group (built-ins win
   collisions). Legacy files are adapted via `adapt_legacy_to_universal()`
   (flattens `Attributes[0]` into a dict, wraps `Checks` as
   `{provider: [...]}`, infers `attributes_metadata` from the matched Pydantic
   class). Invalid file → logged and **skipped**
   (`load_compliance_framework_universal` returns `None`).

The framework key in both bulk dicts is the JSON basename without `.json` —
that's also the `--compliance` CLI key.

## How Checks Map to Compliance

1. `update_checks_metadata_with_compliance()` attaches, per check, every
   framework requirement that references it (`CheckMetadata.Compliance`).
2. During output, `get_check_compliance()`
   (`prowler/lib/outputs/compliance/compliance_check.py`) returns the
   per-finding dict `{"{Framework}-{Version}": [requirement_ids]}` — the
   `-{Version}` suffix only exists when `Version` is non-empty.
3. `ConfigRequirements` guardrails are evaluated by
   `evaluate_config_constraints()` (`compliance_config_eval.py`); a violated
   constraint forces FAIL and prepends
   `Configuration not valid for this requirement.` to `status_extended` in
   every output format.

## File Naming Conventions

```text
prowler/compliance/{framework}_{version}.json               # universal
prowler/compliance/{provider}/{framework}_{version}_{provider}.json  # legacy
```

Examples: `dora_2022_2554.json`, `cis_controls_8.1.json`, `cis_7.0_aws.json`,
`iso27001_2022_azure.json`, `okta_idaas_stig_v1r2_okta.json`,
`cisa_scuba_0.6_googleworkspace.json`, `ccc_aws.json` (unversioned only when
the framework has no versioning). For legacy files the version substring in
the filename must equal `Version`.

## Validation Summary

- **Load time (universal)**: `attributes_metadata` root validator — required
  keys, unknown-key drift guard, enums, int/float/bool types. Omit the
  metadata and nothing is validated.
- **Load time (legacy)**: Pydantic attribute-class matching; a shape matching
  no specific class silently falls through to Generic.
- **Never validated at load**: check-id existence. Cross-check manually
  (see SKILL.md → Validation).
- **Test suite**: `tests/lib/check/universal_compliance_models_test.py::test_loads_as_universal`
  is parametrized over every shipped JSON (top-level + per-provider).
- **CI**: `.github/workflows/pr-check-compliance-mapping.yml` flags new checks
  not mapped in any framework (`needs-compliance-review` label; opt out with
  `no-compliance-check`).
- **Pre-commit**: `check-json` + `pretty-format-json` only (syntax/format, no
  semantics).
- **Manual**: `skills/prowler-compliance-review/assets/validate_compliance.py`
  (legacy schema only).

## Repo Tooling (`util/compliance/`)

| Tool | Purpose |
|------|---------|
| `util/compliance/generate_json_from_csv/*.py` | CSV→JSON generators (CIS 1.5, CIS 2.0 GCP, CIS 1.0 GitHub, CIS 4.0 M365, ENS, ThreatScore) |
| `util/compliance/ccc/from_yaml_to_json.py` | FINOS CCC YAML→JSON converter |
| `util/compliance/compliance_mapper/` | Compliance mapper (see its README) |
| `util/compliance/threatscore/get_prowler_threatscore_from_generic_output.py` | Derive ThreatScore from generic output |

## Prowler ThreatScore Details

Custom Prowler scoring framework. Pillars / ID prefixes: `1.x.x` IAM, `2.x.x`
Attack Surface, `3.x.x` Logging and Monitoring, `4.x.x` Encryption.

Scoring: `LevelOfRisk` 1–5 (5=critical) × `Weight` (values in the shipped
catalogs: 1000 critical / 100 high / 8–10 standard / 1 low). Available for
aws, azure, gcp, kubernetes, m365, alibabacloud.

## External Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [CIS Critical Security Controls](https://www.cisecurity.org/controls)
- [ISO 27001](https://www.iso.org/standard/27001)
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST CSF](https://www.nist.gov/cyberframework)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ENS (Spain)](https://www.ccn-cert.cni.es/es/ens.html)
- [FINOS CCC](https://github.com/finos/common-cloud-controls)
- [CSA CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
- [DORA (EU 2022/2554)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/essential-eight)
- [CISA SCuBA](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [Prowler Docs — Compliance developer guide](https://docs.prowler.com/developer-guide/security-compliance-framework)
