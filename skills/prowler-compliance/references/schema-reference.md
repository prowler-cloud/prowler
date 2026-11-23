# Compliance JSON Schema Reference

Source of truth: `prowler/lib/check/compliance_models.py` (Pydantic v1, `from pydantic.v1 import ...`).
Contributor doc: `docs/developer-guide/security-compliance-framework.mdx`.

## Universal schema (`ComplianceFramework`)

File: `prowler/compliance/<framework>_<version>.json` (top level). Detected as universal when the
JSON has a top-level `requirements` or `attributes_metadata` key (`load_compliance_framework_universal`).

```json
{
  "framework": "DORA",
  "name": "Digital Operational Resilience Act (DORA) 2022/2554",
  "version": "2022/2554",
  "description": "Shown in --list-compliance and reports.",
  "icon": "dora",
  "attributes_metadata": [
    {"key": "Pillar", "label": "Pillar", "type": "str", "required": true,
     "enum": ["ICT Risk Management", "..."],
     "output_formats": {"csv": true, "ocsf": true}},
    {"key": "Article", "type": "str", "required": true}
  ],
  "outputs": {
    "table_config": {"group_by": "Pillar"},
    "pdf_config": {"group_by_field": "Pillar"}
  },
  "requirements": [
    {
      "id": "DORA-Art5",
      "name": "Governance and organisation",
      "description": "Requirement text verbatim from the source.",
      "attributes": {"Pillar": "ICT Risk Management", "Article": "Article 5"},
      "checks": {"aws": ["iam_no_root_access_key"], "azure": [], "gcp": []},
      "config_requirements": [
        {"Check": "iam_user_accesskey_unused", "Provider": "aws",
         "ConfigKey": "max_unused_access_keys_days", "Operator": "lte", "Value": 45}
      ]
    }
  ]
}
```

### Top-level fields

| Field | Required | Notes |
|---|---|---|
| `framework` | Yes | Short id (`DORA`, `CSA-CCM`, `CIS-Controls`, `CMMC`). The UI mapper routes on this value. |
| `name` | Yes | Human-readable name. |
| `version` | No in the model, never leave empty | Part of the `{framework}-{version}` label in outputs. |
| `description` | Yes | |
| `provider` | No | Fallback only; providers are derived from `checks` keys (`get_providers()`). |
| `icon` | No | Short slug. |
| `attributes_metadata` | No (strongly recommended) | Schema of `attributes`. If omitted, no attribute validation runs. |
| `outputs.table_config` | **Effectively required** | `process_universal_compliance_frameworks()` and the universal table only handle frameworks that have it. Without it no compliance CSV/OCSF/table is produced. |
| `outputs.pdf_config` | No | Modeled (`PDFConfig`) but not consumed by the API PDF pipeline. |
| `requirements` | Yes | |

`TableConfig`: `group_by` (required), `split_by` (`{field, values}`), `scoring` (`{risk_field, weight_field}`),
`labels` (`TableLabels`). Nothing validates at load that `group_by` names a declared attribute: keep them in sync.

### Requirement fields (`UniversalComplianceRequirement`)

| Field | Required | Notes |
|---|---|---|
| `id` | Yes | Unique in the file (enforced by `tests/lib/check/compliance_catalog_integrity_test.py`). |
| `description` | Yes | Verbatim from the source. |
| `name` | No | |
| `attributes` | No (`{}`) | Flat dict; keys must be declared in `attributes_metadata` when it exists. |
| `checks` | No (`{}`) | `{provider: [check_ids]}`, lowercase provider keys = directory names under `prowler/providers/`. Empty list = manual for that provider. |
| `config_requirements` | No | Same model as legacy `ConfigRequirements`; set `Provider` on every constraint. |
| `tactics`, `sub_techniques`, `platforms`, `technique_url` | No | MITRE extras (filled when adapting legacy MITRE files). |

### `attributes_metadata` entries (`AttributeMetadata`)

| Field | Notes |
|---|---|
| `key` | Required. |
| `label` | CSV/PDF label. |
| `type` | `str` (default), `int`, `float`, `bool`, `list_str`, `list_dict`. Only `int`/`float`/`bool` are type-checked at load. |
| `enum` | Allowed values, enforced at load. |
| `required` | Enforced at load (key present and non-null). |
| `enum_display`, `enum_order`, `chart_label` | PDF presentation metadata. |
| `output_formats` | `{"csv": bool, "ocsf": bool}`, both default `true`. |

Load-time validation (`ComplianceFramework.validate_attributes_against_metadata`): missing required keys,
unknown keys, enum violations, int/float/bool mismatches. All errors are reported together.

## Legacy schema (`Compliance`)

File: `prowler/compliance/<provider>/<framework>_<version>_<provider>.json`.

```json
{
  "Framework": "CIS",
  "Name": "CIS Amazon Web Services Foundations Benchmark v7.0.0",
  "Version": "7.0",
  "Provider": "AWS",
  "Description": "...",
  "Requirements": [
    {
      "Id": "1.1",
      "Name": "Optional",
      "Description": "...",
      "Attributes": [{ "...": "one object matching an attribute class" }],
      "Checks": ["check_id"],
      "ConfigRequirements": []
    }
  ]
}
```

| Field | Notes |
|---|---|
| `Framework`, `Name`, `Provider` | Required, non-empty (root validator). One provider per file. |
| `Version` | Optional in the model. Empty Version makes `get_check_compliance()` key the finding as `"{Framework}"` instead of `"{Framework}-{Version}"`. |
| `Description`, `Requirements` | Required. |
| `Requirements[].Id`, `Description`, `Attributes`, `Checks` | Required. Only `Attributes[0]` is used by the universal adapter and the UI. |
| `Requirements[].ConfigRequirements` | Optional; `Provider` may be omitted. |

MITRE files use `Mitre_Requirement` (`Name`, `Id`, `Tactics`, `SubTechniques`, `Platforms`, `Description`,
`TechniqueURL`, `Attributes` with `Mitre_Requirement_Attribute_{AWS,Azure,GCP}`, `Checks`).

### Attribute classes (`Compliance_Requirement.Attributes` Union, order is load-bearing)

`ASDEssentialEight`, `CIS`, `ENS`, `ISO27001_2013`, `AWS_Well_Architected`, `KISA_ISMSP`,
`Prowler_ThreatScore`, `CCC`, `C5Germany`, `CSA_CCM`, `STIG`, then `Generic_Compliance_Requirement_Attribute`
LAST. Pydantic v1 tries members in order; an attribute object that matches no specific class becomes Generic
and loses its specific fields.

| Family (file key) | Fields (see the class for Optional vs required) |
|---|---|
| CIS (`cis_{ver}_{provider}`) | `Section`, `SubSection`, `Profile` (`Level 1`, `Level 2`, `E3 Level 1`, `E3 Level 2`, `E5 Level 1`, `E5 Level 2`), `AssessmentStatus` (`Automated`, `Manual`), `Description`, `RationaleStatement`, `ImpactStatement`, `RemediationProcedure`, `AuditProcedure`, `AdditionalInformation`, `DefaultValue`, `References` |
| ENS (`ens_rd2022_{provider}`) | `IdGrupoControl`, `Marco`, `Categoria`, `DescripcionControl`, `Nivel` (`opcional`, `bajo`, `medio`, `alto`), `Tipo` (`refuerzo`, `requisito`, `recomendacion`, `medida`), `Dimensiones` (`confidencialidad`, `integridad`, `trazabilidad`, `autenticidad`, `disponibilidad`), `ModoEjecucion`, `Dependencias` |
| ISO 27001 (`iso27001_{year}_{provider}`) | `Category`, `Objetive_ID`, `Objetive_Name`, `Check_Summary` (the `Objetive` misspelling is the real field name) |
| CCC (`ccc_{provider}`) | `FamilyName`, `FamilyDescription`, `Section`, `SubSection`, `SubSectionObjective`, `Applicability` (TLP tags), `Recommendation`, `SectionThreatMappings`, `SectionGuidelineMappings` |
| ASD Essential Eight (`asd_essential_eight_aws`) | `Section`, `MaturityLevel` (`ML1`-`ML3`), `AssessmentStatus`, `CloudApplicability` (`full`, `partial`, `limited`, `non-applicable`), `MitigatedThreats`, `Description`, `RationaleStatement`, `ImpactStatement`, `RemediationProcedure`, `AuditProcedure`, `AdditionalInformation`, `References` |
| DISA STIG (`okta_idaas_stig_v1r2_okta`) | `Section`, `Severity` (`high`, `medium`, `low`), `RuleID`, `StigID`, `CCI`, `CheckText`, `FixText` |
| AWS Well-Architected | `Name`, `WellArchitectedQuestionId`, `WellArchitectedPracticeId`, `Section`, `SubSection`, `LevelOfRisk`, `AssessmentMethod`, `Description`, `ImplementationGuidanceUrl` |
| KISA ISMS-P | `Domain`, `Subdomain`, `Section`, `AuditChecklist`, `RelatedRegulations`, `AuditEvidence`, `NonComplianceCases` |
| C5 | `Section`, `SubSection`, `Type`, `AboutCriteria`, `ComplementaryCriteria` |
| CSA CCM (legacy shape; shipped CSA CCM 4.0 is universal) | `Section`, `CCMLite`, `IaaS`, `PaaS`, `SaaS`, `ScopeApplicability` |
| Prowler ThreatScore (`prowler_threatscore_{provider}`) | `Title`, `Section`, `SubSection`, `AttributeDescription`, `AdditionalInformation`, `LevelOfRisk`, `Weight` |
| Generic (fallback) | `ItemId`, `Section`, `SubSection`, `SubGroup`, `Service`, `Type`, `Comment` (all optional). Used by NIST, PCI, GDPR, HIPAA, SOC2, FedRAMP rev4, NIS2, SecNumCloud, etc. |

Templates for the common legacy shapes are in `../assets/*_framework.json`.

## Config guardrails (`Compliance_Requirement_ConfigConstraint`)

Force a requirement to FAIL when a configurable check ran with a looser `audit_config` than the control allows.

```json
{"Check": "iam_user_accesskey_unused", "ConfigKey": "max_unused_access_keys_days",
 "Operator": "lte", "Value": 45, "Provider": "aws"}
```

| Operator | Value type (validated at load) | Use |
|---|---|---|
| `lte`, `gte` | number (not bool) | thresholds |
| `eq` | scalar (use JSON booleans, not 0/1) | toggles, exact values |
| `in` | list | scalar must be one of |
| `subset` | list | allowlists (widening breaks it) |
| `superset` | list | denylists (removing an entry breaks it) |

- `Value` = strictest setting the control text tolerates.
- `ConfigKey` must match the key the check reads; if the key is absent from `audit_config` the constraint is skipped.
- `Provider`: mandatory in universal files, matched case-insensitively; optional in legacy files.
- Evaluation: `prowler/lib/check/compliance_config_eval.py` (`evaluate_config_constraints`, `apply_config_status`,
  `get_effective_status`, `CONFIG_NOT_VALID_PREFIX`), shared by CLI outputs and the API. Guardrails only turn
  PASS into FAIL.
- Tests: `tests/lib/check/compliance_config_eval_test.py`, `compliance_config_constraint_model_test.py`,
  `compliance_config_requirements_data_test.py`, `mitre_config_requirements_test.py`, and
  `tests/lib/outputs/compliance/config_status_*_coverage_test.py`.
