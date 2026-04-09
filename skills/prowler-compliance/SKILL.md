---
name: prowler-compliance
description: >
  Creates, syncs, audits and manages Prowler compliance frameworks end-to-end.
  Covers the four-layer architecture (SDK models → JSON catalogs → output
  formatters → API/UI), upstream sync workflows, cloud-auditor check-mapping
  reviews, output formatter creation, and framework-specific attribute models.
  Trigger: When working with compliance frameworks (CIS, NIST, PCI-DSS, SOC2,
  GDPR, ISO27001, ENS, MITRE ATT&CK, CCC, C5, CSA CCM, KISA ISMS-P,
  Prowler ThreatScore, FedRAMP, HIPAA), syncing with upstream catalogs,
  auditing check-to-requirement mappings, adding output formatters, or fixing
  compliance JSON bugs (duplicate IDs, empty Version, wrong Section, stale
  check refs).
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

## When to Use

Use this skill when:
- Creating a new compliance framework for any provider
- **Syncing an existing framework with an upstream source of truth** (CIS, FINOS CCC, CSA CCM, NIST, ENS, etc.)
- Adding requirements to existing frameworks
- Mapping checks to compliance controls
- **Auditing existing check mappings as a cloud auditor** (user asks "are these mappings correct?", "which checks apply to this requirement?", "review the mappings")
- **Adding a new output formatter** (new framework needs a table dispatcher + per-provider classes + CSV models)
- **Fixing JSON bugs**: duplicate IDs, empty Version, wrong Section, stale check refs, inconsistent FamilyName, padded tangential check mappings
- **Registering a framework in the CLI table dispatcher or API export map**
- Investigating why a finding/check isn't showing under the expected compliance framework in the UI
- Understanding compliance framework structures and attributes

## Four-Layer Architecture (Mental Model)

Prowler compliance is a **four-layer system** hanging off one Pydantic model tree. Bugs usually happen where one layer doesn't match another, so know all four before touching anything.

### Layer 1: SDK / Core Models — `prowler/lib/check/`

- **`compliance_models.py`** — Pydantic **v1** model tree (`from pydantic.v1 import`). One `*_Requirement_Attribute` class per framework type + `Generic_Compliance_Requirement_Attribute` as fallback.
- `Compliance_Requirement.Attributes: list[Union[...]]` — **`Generic_Compliance_Requirement_Attribute` MUST be LAST** in the Union or every framework-specific attribute falls through to Generic (Pydantic v1 tries union members in order).
- **`compliance.py`** — runtime linker. `get_check_compliance()` builds the key as `f"{Framework}-{Version}"` **only if `Version` is non-empty**. An empty Version makes the key just `"{Framework}"` — this breaks downstream filters and tests that expect the versioned key.
- `Compliance.get_bulk(provider)` walks `prowler/compliance/{provider}/` and parses every `.json` file. No central index — just directory scan.

### Layer 2: JSON Frameworks — `prowler/compliance/{provider}/`

See "Compliance Framework Location" and "Framework-Specific Attribute Structures" sections below.

### Layer 3: Output Formatters — `prowler/lib/outputs/compliance/{framework}/`

**Every framework directory follows this exact convention** — do not deviate:

```
{framework}/
├── __init__.py
├── {framework}.py            # ONLY get_{framework}_table() — NO function docstring
├── {framework}_{provider}.py # One class per provider (e.g., CCC_AWS, CCC_Azure, CCC_GCP)
└── models.py                 # One Pydantic v2 BaseModel per provider (CSV columns)
```

- **`{framework}.py`** holds the **table dispatcher function** `get_{framework}_table()`. It prints the pass/fail/muted summary table. **Must NOT import `Finding` or `ComplianceOutput`** — doing so creates a circular import with `prowler/lib/outputs/compliance/compliance.py`. Only imports: `colorama`, `tabulate`, `prowler.config.config.orange_color`.
- **`{framework}_{provider}.py`** holds a per-provider class like `CCC_AWS(ComplianceOutput)` with a `transform()` method that walks findings and emits rows. This file IS allowed to import `Finding` because it's not on the dispatcher import chain.
- **`models.py`** holds one Pydantic v2 `BaseModel` per provider. Field names become CSV column headers (**public API** — renaming breaks downstream consumers).
- **Never collapse per-provider files into a unified parameterized class**, even when DRY-tempting. Every framework in Prowler follows the per-provider file pattern and reviewers will reject the refactor. CSV columns differ per provider (`AccountId`/`Region` vs `SubscriptionId`/`Location` vs `ProjectId`/`Location`) — three classes is the convention.
- **No function docstring on `get_{framework}_table()`** — no other framework has one; stay consistent.
- Register in `prowler/lib/outputs/compliance/compliance.py` → `display_compliance_table()` with an `elif compliance_framework.startswith("{framework}_"):` branch. Import the table function at the top of the file.

### Layer 4: API / UI

- **API table dispatcher**: `api/src/backend/tasks/jobs/export.py` → `COMPLIANCE_CLASS_MAP` keyed by provider. Uses `startswith` predicates: `(lambda name: name.startswith("ccc_"), CCC_AWS)`. **Never use exact match** (`name == "ccc_aws"`) — it's inconsistent and breaks versioning.
- **API lazy loader**: `api/src/backend/api/compliance.py` — `LazyComplianceTemplate` and `LazyChecksMapping` load compliance per provider on first access.
- **UI mapper routing**: `ui/lib/compliance/compliance-mapper.ts` routes framework names → per-framework mapper.
- **UI per-framework mapper**: `ui/lib/compliance/{framework}.tsx` flattens `Requirements` into a 3-level tree (Framework → Category → Control → Requirement) for the accordion view. Groups by `Attributes[0].FamilyName` and `Attributes[0].Section`.
- **UI detail panel**: `ui/components/compliance/compliance-custom-details/{framework}-details.tsx`.
- **UI types**: `ui/types/compliance.ts` — TypeScript mirrors of the attribute metadata.

### The CLI Pipeline (end-to-end)

```
prowler aws --compliance ccc_aws
    ↓
Compliance.get_bulk("aws")  → parses prowler/compliance/aws/*.json
    ↓
update_checks_metadata_with_compliance()  → attaches compliance info to CheckMetadata
    ↓
execute_checks()  → runs checks, produces Finding objects
    ↓
get_check_compliance(finding, "aws", bulk_checks_metadata)
    → dict "{Framework}-{Version}" → [requirement_ids]
    ↓
CCC_AWS(findings, compliance).transform()  → per-provider class builds CSV rows
    ↓
batch_write_data_to_file()  → writes {output_filename}_ccc_aws.csv
    ↓
display_compliance_table() → get_ccc_table() → prints stdout summary
```

---

## Compliance Framework Location

Frameworks are JSON files located in: `prowler/compliance/{provider}/{framework_name}_{provider}.json`

**Supported Providers:**
- `aws` - Amazon Web Services
- `azure` - Microsoft Azure
- `gcp` - Google Cloud Platform
- `kubernetes` - Kubernetes
- `github` - GitHub
- `m365` - Microsoft 365
- `alibabacloud` - Alibaba Cloud
- `cloudflare` - Cloudflare
- `oraclecloud` - Oracle Cloud
- `oci` - Oracle Cloud Infrastructure
- `nhn` - NHN Cloud
- `mongodbatlas` - MongoDB Atlas
- `iac` - Infrastructure as Code
- `llm` - Large Language Models

## Base Framework Structure

All compliance frameworks share this base structure:

```json
{
  "Framework": "FRAMEWORK_NAME",
  "Name": "Full Framework Name with Version",
  "Version": "X.X",
  "Provider": "PROVIDER",
  "Description": "Framework description...",
  "Requirements": [
    {
      "Id": "requirement_id",
      "Description": "Requirement description",
      "Name": "Optional requirement name",
      "Attributes": [...],
      "Checks": ["check_name_1", "check_name_2"]
    }
  ]
}
```

## Framework-Specific Attribute Structures

Each framework type has its own attribute model. Below are the exact structures used by Prowler:

### CIS (Center for Internet Security)

**Framework ID format:** `cis_{version}_{provider}` (e.g., `cis_5.0_aws`)

```json
{
  "Id": "1.1",
  "Description": "Maintain current contact details",
  "Checks": ["account_maintain_current_contact_details"],
  "Attributes": [
    {
      "Section": "1 Identity and Access Management",
      "SubSection": "Optional subsection",
      "Profile": "Level 1",
      "AssessmentStatus": "Automated",
      "Description": "Detailed attribute description",
      "RationaleStatement": "Why this control matters",
      "ImpactStatement": "Impact of implementing this control",
      "RemediationProcedure": "Steps to fix the issue",
      "AuditProcedure": "Steps to verify compliance",
      "AdditionalInformation": "Extra notes",
      "DefaultValue": "Default configuration value",
      "References": "https://docs.example.com/reference"
    }
  ]
}
```

**Profile values:** `Level 1`, `Level 2`, `E3 Level 1`, `E3 Level 2`, `E5 Level 1`, `E5 Level 2`
**AssessmentStatus values:** `Automated`, `Manual`

---

### ISO 27001

**Framework ID format:** `iso27001_{year}_{provider}` (e.g., `iso27001_2022_aws`)

```json
{
  "Id": "A.5.1",
  "Description": "Policies for information security should be defined...",
  "Name": "Policies for information security",
  "Checks": ["securityhub_enabled"],
  "Attributes": [
    {
      "Category": "A.5 Organizational controls",
      "Objetive_ID": "A.5.1",
      "Objetive_Name": "Policies for information security",
      "Check_Summary": "Summary of what is being checked"
    }
  ]
}
```

**Note:** `Objetive_ID` and `Objetive_Name` use this exact spelling (not "Objective").

---

### ENS (Esquema Nacional de Seguridad - Spain)

**Framework ID format:** `ens_rd2022_{provider}` (e.g., `ens_rd2022_aws`)

```json
{
  "Id": "op.acc.1.aws.iam.2",
  "Description": "Proveedor de identidad centralizado",
  "Checks": ["iam_check_saml_providers_sts"],
  "Attributes": [
    {
      "IdGrupoControl": "op.acc.1",
      "Marco": "operacional",
      "Categoria": "control de acceso",
      "DescripcionControl": "Detailed control description in Spanish",
      "Nivel": "alto",
      "Tipo": "requisito",
      "Dimensiones": ["trazabilidad", "autenticidad"],
      "ModoEjecucion": "automatico",
      "Dependencias": []
    }
  ]
}
```

**Nivel values:** `opcional`, `bajo`, `medio`, `alto`
**Tipo values:** `refuerzo`, `requisito`, `recomendacion`, `medida`
**Dimensiones values:** `confidencialidad`, `integridad`, `trazabilidad`, `autenticidad`, `disponibilidad`

---

### MITRE ATT&CK

**Framework ID format:** `mitre_attack_{provider}` (e.g., `mitre_attack_aws`)

MITRE uses a different requirement structure:

```json
{
  "Name": "Exploit Public-Facing Application",
  "Id": "T1190",
  "Tactics": ["Initial Access"],
  "SubTechniques": [],
  "Platforms": ["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
  "Description": "Adversaries may attempt to exploit a weakness...",
  "TechniqueURL": "https://attack.mitre.org/techniques/T1190/",
  "Checks": ["guardduty_is_enabled", "inspector2_is_enabled"],
  "Attributes": [
    {
      "AWSService": "Amazon GuardDuty",
      "Category": "Detect",
      "Value": "Minimal",
      "Comment": "Explanation of how this service helps..."
    }
  ]
}
```

**For Azure:** Use `AzureService` instead of `AWSService`
**For GCP:** Use `GCPService` instead of `AWSService`
**Category values:** `Detect`, `Protect`, `Respond`
**Value values:** `Minimal`, `Partial`, `Significant`

---

### NIST 800-53

**Framework ID format:** `nist_800_53_revision_{version}_{provider}` (e.g., `nist_800_53_revision_5_aws`)

```json
{
  "Id": "ac_2_1",
  "Name": "AC-2(1) Automated System Account Management",
  "Description": "Support the management of system accounts...",
  "Checks": ["iam_password_policy_minimum_length_14"],
  "Attributes": [
    {
      "ItemId": "ac_2_1",
      "Section": "Access Control (AC)",
      "SubSection": "Account Management (AC-2)",
      "SubGroup": "AC-2(3) Disable Accounts",
      "Service": "iam"
    }
  ]
}
```

---

### Generic Compliance (Fallback)

For frameworks without specific attribute models:

```json
{
  "Id": "requirement_id",
  "Description": "Requirement description",
  "Name": "Optional name",
  "Checks": ["check_name"],
  "Attributes": [
    {
      "ItemId": "item_id",
      "Section": "Section name",
      "SubSection": "Subsection name",
      "SubGroup": "Subgroup name",
      "Service": "service_name",
      "Type": "type"
    }
  ]
}
```

---

### AWS Well-Architected Framework

**Framework ID format:** `aws_well_architected_framework_{pillar}_pillar_aws`

```json
{
  "Id": "SEC01-BP01",
  "Description": "Establish common guardrails...",
  "Name": "Establish common guardrails",
  "Checks": ["account_part_of_organizations"],
  "Attributes": [
    {
      "Name": "Establish common guardrails",
      "WellArchitectedQuestionId": "securely-operate",
      "WellArchitectedPracticeId": "sec_securely_operate_multi_accounts",
      "Section": "Security",
      "SubSection": "Security foundations",
      "LevelOfRisk": "High",
      "AssessmentMethod": "Automated",
      "Description": "Detailed description",
      "ImplementationGuidanceUrl": "https://docs.aws.amazon.com/..."
    }
  ]
}
```

---

### KISA ISMS-P (Korea)

**Framework ID format:** `kisa_isms_p_{year}_{provider}` (e.g., `kisa_isms_p_2023_aws`)

```json
{
  "Id": "1.1.1",
  "Description": "Requirement description",
  "Name": "Requirement name",
  "Checks": ["check_name"],
  "Attributes": [
    {
      "Domain": "1. Management System",
      "Subdomain": "1.1 Management System Establishment",
      "Section": "1.1.1 Section Name",
      "AuditChecklist": ["Checklist item 1", "Checklist item 2"],
      "RelatedRegulations": ["Regulation 1"],
      "AuditEvidence": ["Evidence type 1"],
      "NonComplianceCases": ["Non-compliance example"]
    }
  ]
}
```

---

### C5 (Germany Cloud Computing Compliance Criteria Catalogue)

**Framework ID format:** `c5_{provider}` (e.g., `c5_aws`)

```json
{
  "Id": "BCM-01",
  "Description": "Requirement description",
  "Name": "Requirement name",
  "Checks": ["check_name"],
  "Attributes": [
    {
      "Section": "BCM Business Continuity Management",
      "SubSection": "BCM-01",
      "Type": "Basic Criteria",
      "AboutCriteria": "Description of criteria",
      "ComplementaryCriteria": "Additional criteria"
    }
  ]
}
```

---

### CCC (Cloud Computing Compliance)

**Framework ID format:** `ccc_{provider}` (e.g., `ccc_aws`)

```json
{
  "Id": "CCC.C01",
  "Description": "Requirement description",
  "Name": "Requirement name",
  "Checks": ["check_name"],
  "Attributes": [
    {
      "FamilyName": "Cryptography & Key Management",
      "FamilyDescription": "Family description",
      "Section": "CCC.C01",
      "SubSection": "Key Management",
      "SubSectionObjective": "Objective description",
      "Applicability": ["IaaS", "PaaS", "SaaS"],
      "Recommendation": "Recommended action",
      "SectionThreatMappings": [{"threat": "T1190"}],
      "SectionGuidelineMappings": [{"guideline": "NIST"}]
    }
  ]
}
```

---

### Prowler ThreatScore

**Framework ID format:** `prowler_threatscore_{provider}` (e.g., `prowler_threatscore_aws`)

Prowler ThreatScore is a custom security scoring framework developed by Prowler that evaluates AWS account security based on **four main pillars**:

| Pillar | Description |
|--------|-------------|
| **1. IAM** | Identity and Access Management controls (authentication, authorization, credentials) |
| **2. Attack Surface** | Network exposure, public resources, security group rules |
| **3. Logging and Monitoring** | Audit logging, threat detection, forensic readiness |
| **4. Encryption** | Data at rest and in transit encryption |

**Scoring System:**
- **LevelOfRisk** (1-5): Severity of the security issue
  - `5` = Critical (e.g., root MFA, public S3 buckets)
  - `4` = High (e.g., user MFA, public EC2)
  - `3` = Medium (e.g., password policies, encryption)
  - `2` = Low
  - `1` = Informational
- **Weight**: Impact multiplier for score calculation
  - `1000` = Critical controls (root security, public exposure)
  - `100` = High-impact controls (user authentication, monitoring)
  - `10` = Standard controls (password policies, encryption)
  - `1` = Low-impact controls (best practices)

```json
{
  "Id": "1.1.1",
  "Description": "Ensure MFA is enabled for the 'root' user account",
  "Checks": ["iam_root_mfa_enabled"],
  "Attributes": [
    {
      "Title": "MFA enabled for 'root'",
      "Section": "1. IAM",
      "SubSection": "1.1 Authentication",
      "AttributeDescription": "The root user account holds the highest level of privileges within an AWS account. Enabling MFA enhances security by adding an additional layer of protection.",
      "AdditionalInformation": "Enabling MFA enhances console security by requiring the authenticating user to both possess a time-sensitive key-generating device and have knowledge of their credentials.",
      "LevelOfRisk": 5,
      "Weight": 1000
    }
  ]
}
```

**Available for providers:** AWS, Kubernetes, M365

---

## Available Compliance Frameworks

### AWS (41 frameworks)
| Framework | File Name |
|-----------|-----------|
| CIS 1.4, 1.5, 2.0, 3.0, 4.0, 5.0 | `cis_{version}_aws.json` |
| ISO 27001:2013, 2022 | `iso27001_{year}_aws.json` |
| NIST 800-53 Rev 4, 5 | `nist_800_53_revision_{version}_aws.json` |
| NIST 800-171 Rev 2 | `nist_800_171_revision_2_aws.json` |
| NIST CSF 1.1, 2.0 | `nist_csf_{version}_aws.json` |
| PCI DSS 3.2.1, 4.0 | `pci_{version}_aws.json` |
| HIPAA | `hipaa_aws.json` |
| GDPR | `gdpr_aws.json` |
| SOC 2 | `soc2_aws.json` |
| FedRAMP Low/Moderate | `fedramp_{level}_revision_4_aws.json` |
| ENS RD2022 | `ens_rd2022_aws.json` |
| MITRE ATT&CK | `mitre_attack_aws.json` |
| C5 Germany | `c5_aws.json` |
| CISA | `cisa_aws.json` |
| FFIEC | `ffiec_aws.json` |
| RBI Cyber Security | `rbi_cyber_security_framework_aws.json` |
| AWS Well-Architected | `aws_well_architected_framework_{pillar}_pillar_aws.json` |
| AWS FTR | `aws_foundational_technical_review_aws.json` |
| GxP 21 CFR Part 11, EU Annex 11 | `gxp_{standard}_aws.json` |
| KISA ISMS-P 2023 | `kisa_isms_p_2023_aws.json` |
| NIS2 | `nis2_aws.json` |

### Azure (15+ frameworks)
| Framework | File Name |
|-----------|-----------|
| CIS 2.0, 2.1, 3.0, 4.0 | `cis_{version}_azure.json` |
| ISO 27001:2022 | `iso27001_2022_azure.json` |
| ENS RD2022 | `ens_rd2022_azure.json` |
| MITRE ATT&CK | `mitre_attack_azure.json` |
| PCI DSS 4.0 | `pci_4.0_azure.json` |
| NIST CSF 2.0 | `nist_csf_2.0_azure.json` |

### GCP (15+ frameworks)
| Framework | File Name |
|-----------|-----------|
| CIS 2.0, 3.0, 4.0 | `cis_{version}_gcp.json` |
| ISO 27001:2022 | `iso27001_2022_gcp.json` |
| HIPAA | `hipaa_gcp.json` |
| MITRE ATT&CK | `mitre_attack_gcp.json` |
| PCI DSS 4.0 | `pci_4.0_gcp.json` |
| NIST CSF 2.0 | `nist_csf_2.0_gcp.json` |

### Kubernetes (6 frameworks)
| Framework | File Name |
|-----------|-----------|
| CIS 1.8, 1.10, 1.11 | `cis_{version}_kubernetes.json` |
| ISO 27001:2022 | `iso27001_2022_kubernetes.json` |
| PCI DSS 4.0 | `pci_4.0_kubernetes.json` |

### Other Providers
- **GitHub:** `cis_1.0_github.json`
- **M365:** `cis_4.0_m365.json`, `iso27001_2022_m365.json`
- **NHN:** `iso27001_2022_nhn.json`

## Workflow A: Sync a Framework With an Upstream Catalog

Use when the framework is maintained upstream (CIS Benchmarks, FINOS CCC, CSA CCM, NIST, ENS, etc.) and Prowler needs to catch up.

### Step 1 — Cache the upstream source

Download every upstream file to a local cache so subsequent iterations don't hit the network. For FINOS CCC:

```bash
mkdir -p /tmp/ccc_upstream
catalogs="core/ccc storage/object management/auditlog management/logging ..."
for p in $catalogs; do
  safe=$(echo "$p" | tr '/' '_')
  gh api "repos/finos/common-cloud-controls/contents/catalogs/$p/controls.yaml" \
    -H "Accept: application/vnd.github.raw" > "/tmp/ccc_upstream/${safe}.yaml"
done
```

### Step 2 — Write a generator script

See [assets/sync_ccc_template.py](assets/sync_ccc_template.py) as a working template (the actual script used to sync Prowler's CCC JSONs with FINOS v2025.10). The skeleton handles:

- **Multiple upstream YAML shapes**. Most FINOS CCC catalogs use `control-families: [...]`, but `storage/object` uses a top-level `controls: [...]` with a `family: "CCC.X.Y"` reference id and no human-readable family name. A sync script that only handles shape 1 **silently drops the shape-2 catalog** — this exact bug dropped ObjStor from Prowler for a full iteration. Handle both shapes or explicitly reject unknown shapes.
- **Whitespace collapse**. Upstream YAML multi-line block scalars (`|`) preserve newlines. Prowler stores descriptions single-line. Collapse with `" ".join(value.split())` before writing to JSON.
- **Foreign-prefix AR id rewriting**. Upstream sometimes aliases requirements across catalogs by keeping the original prefix (e.g., `CCC.AuditLog.CN08.AR01` appears under both `management/auditlog.yaml` and `management/logging.yaml`, nested under `CCC.Logging.CN03`). Prowler's Pydantic model requires unique ids within a catalog file — rewrite the foreign id to fit its parent control: `CCC.AuditLog.CN08.AR01` inside `CCC.Logging.CN03` → `CCC.Logging.CN03.AR01`.
- **Genuine upstream collision renumbering**. Sometimes upstream has a real typo where two different requirements share the same id (e.g., `CCC.Core.CN14.AR02` defined twice for 30-day and 14-day backup variants). Renumber the second copy to the next free AR number (`.AR03`). **Preserve the check mappings** by matching on `(Section, frozenset(Applicability))` since the renumbered id won't match by id.
- **Existing check mapping preservation**. Build TWO lookup maps from the legacy JSON before overwriting: `by_id` (`ar_id → [checks]`) and `by_section` (`(Section, frozenset(Applicability)) → [checks]`). Look up by id first; if the id was rewritten, fall back to section+applicability.
- **FamilyName normalization**. Collapse variants like `"Logging & Monitoring"` / `"Logging and Metrics Publication"` / `"Logging and Monitoring"` to a single canonical value. The UI groups by `Attributes[0].FamilyName` exactly — each variant becomes a separate tree branch.
- **Populate `Version`**. Empty Version breaks `get_check_compliance()` key construction. Use the upstream catalog version (e.g., `"v2025.10"`).

### Step 3 — Validate before committing

```python
from prowler.lib.check.compliance_models import Compliance
for prov in ['aws', 'azure', 'gcp']:
    c = Compliance.parse_file(f"prowler/compliance/{prov}/ccc_{prov}.json")
    print(f"{prov}: {len(c.Requirements)} reqs, version={c.Version}")
```

Any `ValidationError` means the Attribute fields don't match the `*_Requirement_Attribute` model. Either fix the JSON or extend the model in `compliance_models.py` (remember: Generic stays last).

### Step 4 — Verify every check id exists

```python
import json
from pathlib import Path
for prov in ['aws', 'azure', 'gcp']:
    existing = {p.stem.replace('.metadata','')
                for p in Path(f'prowler/providers/{prov}/services').rglob('*.metadata.json')}
    with open(f'prowler/compliance/{prov}/ccc_{prov}.json') as f:
        data = json.load(f)
    refs = {c for r in data['Requirements'] for c in r['Checks']}
    missing = refs - existing
    assert not missing, f"{prov} missing: {missing}"
```

A stale check id silently becomes dead weight — no finding will ever map to it. This pre-validation **must run on every write**; bake it into the generator script.

### Step 5 — Add an attribute model if needed

Only if the framework has fields beyond `Generic_Compliance_Requirement_Attribute`. Add the class to `prowler/lib/check/compliance_models.py` and register it in `Compliance_Requirement.Attributes: list[Union[...]]`. **Generic stays last.**

---

## Workflow B: Audit Check Mappings as a Cloud Auditor

Use when the user asks to review existing mappings ("are these correct?", "verify that the checks apply", "audit the CCC mappings"). This is the highest-value compliance task — it surfaces padded mappings with zero actual coverage and missing mappings for legitimate coverage.

### The golden rule

> A Prowler check's title/risk MUST **literally describe what the requirement text says**. "Related" is not enough. If no check actually addresses the requirement, leave `Checks: []` (MANUAL) — **honest MANUAL is worth more than padded coverage**.

### Audit process

**Step 1 — Build a per-provider check inventory** (cache in `/tmp/`):

```python
import json
from pathlib import Path
for provider in ['aws', 'azure', 'gcp']:
    inv = {}
    for meta in Path(f'prowler/providers/{provider}/services').rglob('*.metadata.json'):
        with open(meta) as f:
            d = json.load(f)
        cid = d.get('CheckID') or meta.stem.replace('.metadata','')
        inv[cid] = {
            'service': d.get('ServiceName', ''),
            'title': d.get('CheckTitle', ''),
            'risk': d.get('Risk', ''),
            'description': d.get('Description', ''),
        }
    with open(f'/tmp/checks_{provider}.json', 'w') as f:
        json.dump(inv, f, indent=2)
```

**Step 2 — Keyword/service query helper** — see [assets/query_checks.py](assets/query_checks.py):

```bash
python assets/query_checks.py aws encryption transit    # keyword AND-search
python assets/query_checks.py aws --service iam         # all iam checks
python assets/query_checks.py aws --id kms_cmk_rotation_enabled  # full metadata
```

**Step 3 — Dump a framework section with current mappings** — see [assets/dump_section.py](assets/dump_section.py):

```bash
python assets/dump_section.py "CCC.Core."      # all Core ARs across 3 providers
python assets/dump_section.py "CCC.AuditLog."  # all AuditLog ARs
```

**Step 4 — Encode explicit REPLACE decisions** — see [assets/audit_framework_template.py](assets/audit_framework_template.py). Structure:

```python
DECISIONS = {}

DECISIONS["CCC.Core.CN01.AR01"] = {
    "aws": [
        "cloudfront_distributions_https_enabled",
        "cloudfront_distributions_origin_traffic_encrypted",
        # ...
    ],
    "azure": [
        "storage_secure_transfer_required_is_enabled",
        "app_minimum_tls_version_12",
        # ...
    ],
    "gcp": [
        "cloudsql_instance_ssl_connections",
    ],
    # Missing provider key = leave the legacy mapping untouched
}

# Empty list = EXPLICITLY MANUAL (overwrites legacy)
DECISIONS["CCC.Core.CN01.AR07"] = {
    "aws": [],   # Prowler has no IANA port/protocol check
    "azure": [],
    "gcp": [],
}
```

**REPLACE, not PATCH.** Encoding every mapping as a full list (not add/remove delta) makes the audit reproducible and surfaces hidden assumptions from the legacy data.

**Step 5 — Pre-validation**. The audit script MUST validate every check id against the inventory and **abort with stderr listing typos**. Common typos caught during a real audit:

- `fsx_file_system_encryption_at_rest_using_kms` (doesn't exist)
- `cosmosdb_account_encryption_at_rest_with_cmk` (doesn't exist)
- `sqlserver_geo_replication` (doesn't exist)
- `redshift_cluster_audit_logging` (should be `redshift_cluster_encrypted_at_rest`)
- `postgresql_flexible_server_require_secure_transport` (should be `postgresql_flexible_server_enforce_ssl_enabled`)
- `storage_secure_transfer_required_enabled` (should be `storage_secure_transfer_required_is_enabled`)
- `sqlserver_minimum_tls_version_12` (should be `sqlserver_recommended_minimal_tls_version`)

**Step 6 — Apply + validate + test**:

```bash
python /path/to/audit_script.py   # applies decisions, pre-validates
python -m pytest tests/lib/outputs/compliance/ tests/lib/check/ -q
```

### Audit Reference Table: Requirement Text → Prowler Checks

Use this table to map CCC-style / NIST-style / ISO-style requirements to the checks that actually verify them. Built from a real audit of 172 CCC ARs × 3 providers.

| Requirement text | AWS checks | Azure checks | GCP checks |
|---|---|---|---|
| **TLS in transit enforced** | `cloudfront_distributions_https_enabled`, `s3_bucket_secure_transport_policy`, `elbv2_ssl_listeners`, `elbv2_insecure_ssl_ciphers`, `elb_ssl_listeners`, `elb_insecure_ssl_ciphers`, `opensearch_service_domains_https_communications_enforced`, `rds_instance_transport_encrypted`, `redshift_cluster_in_transit_encryption_enabled`, `elasticache_redis_cluster_in_transit_encryption_enabled`, `dynamodb_accelerator_cluster_in_transit_encryption_enabled`, `dms_endpoint_ssl_enabled`, `kafka_cluster_in_transit_encryption_enabled`, `transfer_server_in_transit_encryption_enabled`, `glue_database_connections_ssl_enabled`, `sns_subscription_not_using_http_endpoints` | `storage_secure_transfer_required_is_enabled`, `storage_ensure_minimum_tls_version_12`, `postgresql_flexible_server_enforce_ssl_enabled`, `mysql_flexible_server_ssl_connection_enabled`, `mysql_flexible_server_minimum_tls_version_12`, `sqlserver_recommended_minimal_tls_version`, `app_minimum_tls_version_12`, `app_ensure_http_is_redirected_to_https`, `app_ftp_deployment_disabled` | `cloudsql_instance_ssl_connections` (almost only option) |
| **TLS 1.3 specifically** | Partial: `cloudfront_distributions_using_deprecated_ssl_protocols`, `elb*_insecure_ssl_ciphers`, `*_minimum_tls_version_12` | Partial: `*_minimum_tls_version_12` checks | None — accept as MANUAL |
| **SSH / port 22 hardening** | `ec2_instance_port_ssh_exposed_to_internet`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_22` | `network_ssh_internet_access_restricted`, `vm_linux_enforce_ssh_authentication` | `compute_firewall_ssh_access_from_the_internet_allowed`, `compute_instance_block_project_wide_ssh_keys_disabled`, `compute_project_os_login_enabled`, `compute_project_os_login_2fa_enabled` |
| **mTLS (mutual TLS)** | `kafka_cluster_mutual_tls_authentication_enabled`, `apigateway_restapi_client_certificate_enabled` | `app_client_certificates_on` | None — MANUAL |
| **Data at rest encrypted** | `s3_bucket_default_encryption`, `s3_bucket_kms_encryption`, `ec2_ebs_default_encryption`, `ec2_ebs_volume_encryption`, `rds_instance_storage_encrypted`, `rds_cluster_storage_encrypted`, `rds_snapshots_encrypted`, `dynamodb_tables_kms_cmk_encryption_enabled`, `redshift_cluster_encrypted_at_rest`, `neptune_cluster_storage_encrypted`, `documentdb_cluster_storage_encrypted`, `opensearch_service_domains_encryption_at_rest_enabled`, `kinesis_stream_encrypted_at_rest`, `firehose_stream_encrypted_at_rest`, `sns_topics_kms_encryption_at_rest_enabled`, `sqs_queues_server_side_encryption_enabled`, `efs_encryption_at_rest_enabled`, `athena_workgroup_encryption`, `glue_data_catalogs_metadata_encryption_enabled`, `backup_vaults_encrypted`, `backup_recovery_point_encrypted`, `cloudtrail_kms_encryption_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `eks_cluster_kms_cmk_encryption_in_secrets_enabled`, `sagemaker_notebook_instance_encryption_enabled`, `apigateway_restapi_cache_encrypted`, `kafka_cluster_encryption_at_rest_uses_cmk`, `dynamodb_accelerator_cluster_encryption_enabled`, `storagegateway_fileshare_encryption_enabled` | `storage_infrastructure_encryption_is_enabled`, `storage_ensure_encryption_with_customer_managed_keys`, `vm_ensure_attached_disks_encrypted_with_cmk`, `vm_ensure_unattached_disks_encrypted_with_cmk`, `sqlserver_tde_encryption_enabled`, `sqlserver_tde_encrypted_with_cmk`, `databricks_workspace_cmk_encryption_enabled`, `monitor_storage_account_with_activity_logs_cmk_encrypted` | `compute_instance_encryption_with_csek_enabled`, `dataproc_encrypted_with_cmks_disabled`, `bigquery_dataset_cmk_encryption`, `bigquery_table_cmk_encryption` |
| **CMEK required (customer-managed keys)** | `kms_cmk_are_used` | `storage_ensure_encryption_with_customer_managed_keys`, `vm_ensure_attached_disks_encrypted_with_cmk`, `vm_ensure_unattached_disks_encrypted_with_cmk`, `sqlserver_tde_encrypted_with_cmk`, `databricks_workspace_cmk_encryption_enabled` | `bigquery_dataset_cmk_encryption`, `bigquery_table_cmk_encryption`, `dataproc_encrypted_with_cmks_disabled`, `compute_instance_encryption_with_csek_enabled` |
| **Key rotation enabled** | `kms_cmk_rotation_enabled` | `keyvault_key_rotation_enabled`, `storage_key_rotation_90_days` | `kms_key_rotation_enabled` |
| **MFA for UI access** | `iam_root_mfa_enabled`, `iam_root_hardware_mfa_enabled`, `iam_user_mfa_enabled_console_access`, `iam_user_hardware_mfa_enabled`, `iam_administrator_access_with_mfa`, `cognito_user_pool_mfa_enabled` | `entra_privileged_user_has_mfa`, `entra_non_privileged_user_has_mfa`, `entra_user_with_vm_access_has_mfa`, `entra_security_defaults_enabled` | `compute_project_os_login_2fa_enabled` |
| **API access / credentials** | `iam_no_root_access_key`, `iam_user_no_setup_initial_access_key`, `apigateway_restapi_authorizers_enabled`, `apigateway_restapi_public_with_authorizer`, `apigatewayv2_api_authorizers_enabled` | `entra_conditional_access_policy_require_mfa_for_management_api`, `app_function_access_keys_configured`, `app_function_identity_is_configured` | `apikeys_api_restrictions_configured`, `apikeys_key_exists`, `apikeys_key_rotated_in_90_days` |
| **Log all admin/config changes** | `cloudtrail_multi_region_enabled`, `cloudtrail_multi_region_enabled_logging_management_events`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_log_file_validation_enabled`, `cloudwatch_log_metric_filter_*`, `cloudwatch_changes_to_*_alarm_configured`, `config_recorder_all_regions_enabled` | `monitor_diagnostic_settings_exists`, `monitor_diagnostic_setting_with_appropriate_categories`, `monitor_alert_*` | `iam_audit_logs_enabled`, `logging_log_metric_filter_and_alert_for_*`, `logging_sink_created` |
| **Log integrity (digital signatures)** | `cloudtrail_log_file_validation_enabled` (exact) | None | None |
| **Public access denied** | `s3_bucket_public_access`, `s3_bucket_public_list_acl`, `s3_bucket_public_write_acl`, `s3_account_level_public_access_blocks`, `apigateway_restapi_public`, `awslambda_function_url_public`, `awslambda_function_not_publicly_accessible`, `rds_instance_no_public_access`, `rds_snapshots_public_access`, `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`, `sns_topics_not_publicly_accessible`, `sqs_queues_not_publicly_accessible` | `storage_blob_public_access_level_is_disabled`, `storage_ensure_private_endpoints_in_storage_accounts`, `containerregistry_not_publicly_accessible`, `keyvault_private_endpoints`, `app_function_not_publicly_accessible`, `aks_clusters_public_access_disabled`, `network_http_internet_access_restricted` | `cloudstorage_bucket_public_access`, `compute_instance_public_ip`, `cloudsql_instance_public_ip`, `compute_firewall_*_access_from_the_internet_allowed` |
| **IAM least privilege** | `iam_*_no_administrative_privileges`, `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation`, `iam_role_administratoraccess_policy`, `iam_group_administrator_access_policy`, `iam_user_administrator_access_policy`, `iam_policy_attached_only_to_group_or_roles`, `iam_role_cross_service_confused_deputy_prevention` | `iam_role_user_access_admin_restricted`, `iam_subscription_roles_owner_custom_not_created`, `iam_custom_role_has_permissions_to_administer_resource_locks` | `iam_sa_no_administrative_privileges`, `iam_no_service_roles_at_project_level`, `iam_role_kms_enforce_separation_of_duties`, `iam_role_sa_enforce_separation_of_duties` |
| **Password policy** | `iam_password_policy_minimum_length_14`, `iam_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_symbol`, `iam_password_policy_number`, `iam_password_policy_expires_passwords_within_90_days_or_less`, `iam_password_policy_reuse_24` | None | None |
| **Credential rotation / unused** | `iam_rotate_access_key_90_days`, `iam_user_accesskey_unused`, `iam_user_console_access_unused` | None | `iam_sa_user_managed_key_rotate_90_days`, `iam_sa_user_managed_key_unused`, `iam_service_account_unused` |
| **VPC / flow logs** | `vpc_flow_logs_enabled` | `network_flow_log_captured_sent`, `network_watcher_enabled`, `network_flow_log_more_than_90_days` | `compute_subnet_flow_logs_enabled` |
| **Backup / DR / Multi-AZ** | `backup_vaults_exist`, `backup_plans_exist`, `backup_reportplans_exist`, `rds_instance_backup_enabled`, `rds_*_protected_by_backup_plan`, `rds_cluster_multi_az`, `neptune_cluster_backup_enabled`, `documentdb_cluster_backup_enabled`, `efs_have_backup_enabled`, `s3_bucket_cross_region_replication`, `dynamodb_table_protected_by_backup_plan` | `vm_backup_enabled`, `vm_sufficient_daily_backup_retention_period`, `storage_geo_redundant_enabled` | `cloudsql_instance_automated_backups`, `cloudstorage_bucket_log_retention_policy_lock`, `cloudstorage_bucket_sufficient_retention_period` |
| **Access analysis / discovery** | `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings` | None specific | `iam_account_access_approval_enabled`, `iam_cloud_asset_inventory_enabled` |
| **Object lock / retention** | `s3_bucket_object_lock`, `s3_bucket_object_versioning`, `s3_bucket_lifecycle_enabled`, `cloudtrail_bucket_requires_mfa_delete`, `s3_bucket_no_mfa_delete` | `storage_ensure_soft_delete_is_enabled`, `storage_blob_versioning_is_enabled`, `storage_ensure_file_shares_soft_delete_is_enabled` | `cloudstorage_bucket_log_retention_policy_lock`, `cloudstorage_bucket_soft_delete_enabled`, `cloudstorage_bucket_versioning_enabled`, `cloudstorage_bucket_sufficient_retention_period` |
| **Uniform bucket-level access** | `s3_bucket_acl_prohibited` | `storage_account_key_access_disabled`, `storage_default_to_entra_authorization_enabled` | `cloudstorage_bucket_uniform_bucket_level_access` |
| **Container vulnerability scanning** | `ecr_registry_scan_images_on_push_enabled`, `ecr_repositories_scan_vulnerabilities_in_latest_image` | `defender_container_images_scan_enabled`, `defender_container_images_resolved_vulnerabilities` | `artifacts_container_analysis_enabled`, `gcr_container_scanning_enabled` |
| **WAF / rate limiting** | `wafv2_webacl_with_rules`, `waf_*_webacl_with_rules`, `wafv2_webacl_logging_enabled`, `waf_global_webacl_logging_enabled` | None | None |
| **Deployment region restriction** | `organizations_scp_check_deny_regions` | None | None |
| **Secrets automatic rotation** | `secretsmanager_automatic_rotation_enabled`, `secretsmanager_secret_rotated_periodically` | `keyvault_rbac_secret_expiration_set`, `keyvault_non_rbac_secret_expiration_set` | None |
| **Certificate management** | `acm_certificates_expiration_check`, `acm_certificates_with_secure_key_algorithms`, `acm_certificates_transparency_logs_enabled` | `keyvault_key_expiration_set_in_non_rbac`, `keyvault_rbac_key_expiration_set`, `keyvault_non_rbac_secret_expiration_set` | None |
| **GenAI guardrails / input/output filtering** | `bedrock_guardrail_prompt_attack_filter_enabled`, `bedrock_guardrail_sensitive_information_filter_enabled`, `bedrock_agent_guardrail_enabled`, `bedrock_model_invocation_logging_enabled`, `bedrock_api_key_no_administrative_privileges`, `bedrock_api_key_no_long_term_credentials` | None | None |
| **ML dev environment security** | `sagemaker_notebook_instance_root_access_disabled`, `sagemaker_notebook_instance_without_direct_internet_access_configured`, `sagemaker_notebook_instance_vpc_settings_configured`, `sagemaker_models_vpc_settings_configured`, `sagemaker_training_jobs_vpc_settings_configured`, `sagemaker_training_jobs_network_isolation_enabled`, `sagemaker_training_jobs_volume_and_output_encryption_enabled` | None | None |
| **Threat detection / anomalous behavior** | `cloudtrail_threat_detection_enumeration`, `cloudtrail_threat_detection_privilege_escalation`, `cloudtrail_threat_detection_llm_jacking`, `guardduty_is_enabled`, `guardduty_no_high_severity_findings` | None | None |
| **Serverless private access** | `awslambda_function_inside_vpc`, `awslambda_function_not_publicly_accessible`, `awslambda_function_url_public` | `app_function_not_publicly_accessible` | None |

### What Prowler Does NOT Cover (accept MANUAL honestly)

Don't pad mappings for these — mark `Checks: []` and move on:

- **TLS 1.3 version specifically** — Prowler verifies TLS is enforced, not always the exact version
- **IANA port-protocol consistency** — no check for "protocol running on its assigned port"
- **mTLS on most Azure/GCP services** — limited to App Service client certs on Azure, nothing on GCP
- **Rate limiting** on monitoring endpoints, load balancers, serverless invocations, vector ingestion
- **Session cookie expiry** (LB stickiness)
- **HTTP header scrubbing** (Server, X-Powered-By)
- **Certificate transparency verification for imports**
- **Model version pinning, red teaming, AI quality review**
- **Vector embedding validation, dimensional constraints, ANN vs exact search**
- **Secret region replication** (cross-region residency)
- **Lifecycle cleanup policies on container registries**
- **Row-level / column-level security in data warehouses**
- **Deployment region restriction on Azure/GCP** (AWS has `organizations_scp_check_deny_regions`, others don't)
- **Cross-tenant alert silencing permissions**
- **Field-level masking in logs**
- **Managed view enforcement for database access**
- **Automatic MFA delete on all S3 buckets** (only CloudTrail bucket variant exists for some frameworks — AWS has the generic `s3_bucket_no_mfa_delete` though)

---

## Workflow C: Add a New Output Formatter

Use when a new framework needs its own CSV columns or terminal table. Follow the c5/csa/ens layout exactly:

```bash
mkdir -p prowler/lib/outputs/compliance/{framework}
touch prowler/lib/outputs/compliance/{framework}/__init__.py
```

### Step 1 — Create `{framework}.py` (table dispatcher ONLY)

Copy from `prowler/lib/outputs/compliance/c5/c5.py` and change the function name + framework string. The `diff` between your file and `c5.py` should be just those two lines. **No function docstring** — other frameworks don't have one, stay consistent.

### Step 2 — Create `models.py`

One Pydantic v2 `BaseModel` per provider. Field names become CSV column headers (public API — don't rename later without a migration).

```python
from typing import Optional
from pydantic import BaseModel

class {Framework}_AWSModel(BaseModel):
    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    # ... provider-specific columns
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
```

### Step 3 — Create `{framework}_{provider}.py` for each provider

Copy from `prowler/lib/outputs/compliance/c5/c5_aws.py` etc. Contains the `{Framework}_AWS(ComplianceOutput)` class with `transform()` that walks findings and emits model rows. This file IS allowed to import `Finding`.

### Step 4 — Register everywhere

**`prowler/lib/outputs/compliance/compliance.py`** (CLI table dispatcher):
```python
from prowler.lib.outputs.compliance.{framework}.{framework} import get_{framework}_table

def display_compliance_table(...):
    ...
    elif compliance_framework.startswith("{framework}_"):
        get_{framework}_table(findings, bulk_checks_metadata,
                              compliance_framework, output_filename,
                              output_directory, compliance_overview)
```

**`prowler/__main__.py`** (CLI output writer per provider):
Add imports at the top:
```python
from prowler.lib.outputs.compliance.{framework}.{framework}_aws import {Framework}_AWS
from prowler.lib.outputs.compliance.{framework}.{framework}_azure import {Framework}_Azure
from prowler.lib.outputs.compliance.{framework}.{framework}_gcp import {Framework}_GCP
```
Add provider-specific `elif compliance_name.startswith("{framework}_"):` branches that instantiate the class and call `batch_write_data_to_file()`.

**`api/src/backend/tasks/jobs/export.py`** (API export dispatcher):
```python
from prowler.lib.outputs.compliance.{framework}.{framework}_aws import {Framework}_AWS
# ... azure, gcp

COMPLIANCE_CLASS_MAP = {
    "aws": [
        # ...
        (lambda name: name.startswith("{framework}_"), {Framework}_AWS),
    ],
    # ... azure, gcp
}
```

**Always use `startswith`**, never `name == "framework_aws"`. Exact match is a regression.

### Step 5 — Add tests

Create `tests/lib/outputs/compliance/{framework}/` with `{framework}_aws_test.py`, `{framework}_azure_test.py`, `{framework}_gcp_test.py`. See the test template in [references/test_template.md](references/test_template.md).

Add fixtures to `tests/lib/outputs/compliance/fixtures.py`: one `Compliance` object per provider with 1 evaluated + 1 manual requirement to exercise both code paths in `transform()`.

### Circular import warning

**The table dispatcher file (`{framework}.py`) MUST NOT import `Finding`** (directly or transitively). The cycle is:

```
compliance.compliance imports get_{framework}_table
  → {framework}.py imports ComplianceOutput
  → compliance_output imports Finding
  → finding imports get_check_compliance from compliance.compliance
  → CIRCULAR
```

Keep `{framework}.py` bare — only `colorama`, `tabulate`, `prowler.config.config`. Put anything that imports `Finding` in the per-provider `{framework}_{provider}.py` files.

---

## Conventions and Hard-Won Gotchas

These are lessons from the FINOS CCC v2025.10 sync + 172-AR audit pass (April 2026). Learn them once; save days of debugging.

1. **Per-provider files are non-negotiable.** Never collapse `{framework}_aws.py`, `{framework}_azure.py`, `{framework}_gcp.py` into a single parameterized class, no matter how DRY-tempting. Every other framework in the codebase follows the per-provider pattern and reviewers will reject the refactor. The CSV column names differ per provider — three classes is the convention.
2. **`{framework}.py` has NO function docstring.** Other frameworks don't have them. Don't add one to be "helpful".
3. **Circular import protection**: the table dispatcher file MUST NOT import `Finding` (directly or transitively). Split the code so `{framework}.py` only has `get_{framework}_table()` with bare imports, and `{framework}_{provider}.py` holds the class that needs `Finding`.
4. **`Generic_Compliance_Requirement_Attribute` is the fallback** — in the `Compliance_Requirement.Attributes` Union in `compliance_models.py`, Generic MUST be LAST because Pydantic v1 tries union members in order. Putting Generic first means every framework-specific attribute falls through to Generic and the specific model is never used.
5. **Pydantic v1 imports.** `from pydantic.v1 import BaseModel` in `compliance_models.py` — not v2. Mixing causes validation errors. Pydantic v2 is used in the CSV models (`models.py`) — that's fine because they're separate trees.
6. **`get_check_compliance()` key format** is `f"{Framework}-{Version}"` ONLY if Version is set. Empty Version → key is `"{Framework}"` (no version suffix). Tests that mock compliance dicts must match this exact format — when a framework ships with `Version: ""`, downstream code and tests break silently.
7. **CSV column names from `models.py` are public API.** Don't rename a field without migrating downstream consumers — CSV headers change.
8. **Upstream YAML multi-line scalars** (`|` block scalars) preserve newlines. Collapse to single-line with `" ".join(value.split())` before writing to JSON.
9. **Upstream catalogs can use multiple shapes.** FINOS CCC uses `control-families: [...]` in most catalogs but `controls: [...]` at the top level in `storage/object`. Any sync script must handle both or silently drop entire catalogs.
10. **Foreign-prefix AR ids.** Upstream sometimes "imports" requirements from one catalog into another by keeping the original id prefix (e.g., `CCC.AuditLog.CN08.AR01` appearing under `CCC.Logging.CN03`). Prowler's compliance model requires unique ids within a catalog — rewrite the foreign id to fit the parent control: `CCC.AuditLog.CN08.AR01` (inside `CCC.Logging.CN03`) → `CCC.Logging.CN03.AR01`.
11. **Genuine upstream id collisions.** Sometimes upstream has a real typo where two different requirements share the same id (e.g., `CCC.Core.CN14.AR02` defined twice for 30-day and 14-day backup variants). Renumber the second copy to the next free AR number. Preserve check mappings by matching on `(Section, frozenset(Applicability))` since the renumbered id won't match by id.
12. **`COMPLIANCE_CLASS_MAP` in `export.py` uses `startswith` predicates** for all modern frameworks. Exact match (`name == "ccc_aws"`) is an anti-pattern — it was present for CCC until April 2026 and was the reason CCC couldn't have versioned variants.
13. **Pre-validate every check id** against the per-provider inventory before writing the JSON. A typo silently creates an unreferenced check that will fail when findings try to map to it. The audit script MUST abort with stderr listing typos, not swallow them.
14. **REPLACE is better than PATCH** for audit decisions. Encoding every mapping explicitly makes the audit reproducible and surfaces hidden assumptions from the legacy data. A PATCH system that adds/removes is too easy to forget.
15. **When no check applies, MANUAL is correct.** Do not pad mappings with tangential checks "just in case". Prowler's compliance reports are meant to be actionable — padding them with noise breaks that. Honest manual reqs can be mapped later when new checks land.
16. **UI groups by `Attributes[0].FamilyName` and `Attributes[0].Section`.** If FamilyName has inconsistent variants within the same JSON (e.g., "Logging & Monitoring" vs "Logging and Monitoring"), the UI renders them as separate categories. Section empty → the requirement falls into an orphan control with label "". Normalize before shipping.
17. **Provider coverage is asymmetric.** AWS has dense coverage (~586 checks across 80+ services): in-transit encryption, IAM, database encryption, backup. Azure (~167 checks) and GCP (~102 checks) are thinner especially for in-transit encryption, mTLS, and ML/AI. Accept the asymmetry in mappings — don't force GCP parity where Prowler genuinely can't verify.

---

## Useful One-Liners

```bash
# Count requirements per service prefix (CCC, CIS sections, etc.)
jq -r '.Requirements[].Id | split(".")[1]' prowler/compliance/aws/ccc_aws.json | sort | uniq -c

# Find duplicate requirement IDs
jq -r '.Requirements[].Id' file.json | sort | uniq -d

# Count manual requirements (no checks)
jq '[.Requirements[] | select((.Checks | length) == 0)] | length' file.json

# List all unique check references in a framework
jq -r '.Requirements[].Checks[]' file.json | sort -u

# List all unique Sections (to spot inconsistency)
jq '[.Requirements[].Attributes[0].Section] | unique' file.json

# List all unique FamilyNames (to spot inconsistency)
jq '[.Requirements[].Attributes[0].FamilyName] | unique' file.json

# Diff requirement ids between two versions of the same framework
diff <(jq -r '.Requirements[].Id' a.json | sort) <(jq -r '.Requirements[].Id' b.json | sort)

# Find where a check id is used across all frameworks
grep -rl "my_check_name" prowler/compliance/

# Check if a Prowler check exists
find prowler/providers/aws/services -name "{check_id}.metadata.json"

# Validate a JSON with Pydantic
python -c "from prowler.lib.check.compliance_models import Compliance; print(Compliance.parse_file('prowler/compliance/aws/ccc_aws.json').Framework)"
```

---

## Best Practices

1. **Requirement IDs**: Follow the original framework numbering exactly (e.g., "1.1", "A.5.1", "T1190", "ac_2_1")
2. **Check Mapping**: Map to existing checks when possible. Use `Checks: []` for manual-only requirements — honest MANUAL beats padded coverage
3. **Completeness**: Include all framework requirements, even those without automated checks
4. **Version Control**: Include framework version in `Name` and `Version` fields. **Never leave `Version: ""`** — it breaks `get_check_compliance()` key format
5. **File Naming**: Use format `{framework}_{version}_{provider}.json`
6. **Validation**: Prowler validates JSON against Pydantic models at startup — invalid JSON will cause errors
7. **Pre-validate check ids** against the provider's `*.metadata.json` inventory before every commit
8. **Normalize FamilyName and Section** to avoid inconsistent UI tree branches
9. **Register everywhere**: SDK model (if needed) → `compliance.py` dispatcher → `__main__.py` CLI writer → `export.py` API map → UI mapper. Skipping any layer results in silent failures
10. **Audit, don't pad**: when reviewing mappings, apply the golden rule — the check's title/risk MUST literally describe what the requirement text says. Tangential relation doesn't count

## Commands

```bash
# List available frameworks for a provider
prowler {provider} --list-compliance

# Run scan with specific compliance framework
prowler aws --compliance cis_5.0_aws

# Run scan with multiple frameworks
prowler aws --compliance cis_5.0_aws pci_4.0_aws

# Output compliance report in multiple formats
prowler aws --compliance cis_5.0_aws -M csv json html
```

## Code References

### Layer 1 — SDK / Core
- **Compliance Models:** `prowler/lib/check/compliance_models.py` (Pydantic v1 model tree)
- **Compliance Processing / Linker:** `prowler/lib/check/compliance.py` (`get_check_compliance`, `update_checks_metadata_with_compliance`)
- **Check Utils:** `prowler/lib/check/utils.py` (`list_compliance_modules`)

### Layer 2 — JSON Catalogs
- **Framework JSONs:** `prowler/compliance/{provider}/` (auto-discovered via directory walk)

### Layer 3 — Output Formatters
- **Per-framework folders:** `prowler/lib/outputs/compliance/{framework}/`
- **Shared base class:** `prowler/lib/outputs/compliance/compliance_output.py` (`ComplianceOutput` + `batch_write_data_to_file`)
- **CLI table dispatcher:** `prowler/lib/outputs/compliance/compliance.py` (`display_compliance_table`)
- **Finding model:** `prowler/lib/outputs/finding.py` (**do not import transitively from table dispatcher files — circular import**)
- **CLI writer:** `prowler/__main__.py` (per-provider `elif compliance_name.startswith(...)` branches that instantiate per-provider classes)

### Layer 4 — API / UI
- **API lazy loader:** `api/src/backend/api/compliance.py` (`LazyComplianceTemplate`, `LazyChecksMapping`)
- **API export dispatcher:** `api/src/backend/tasks/jobs/export.py` (`COMPLIANCE_CLASS_MAP` with `startswith` predicates)
- **UI framework router:** `ui/lib/compliance/compliance-mapper.ts`
- **UI per-framework mapper:** `ui/lib/compliance/{framework}.tsx`
- **UI detail panel:** `ui/components/compliance/compliance-custom-details/{framework}-details.tsx`
- **UI types:** `ui/types/compliance.ts`
- **UI icon:** `ui/components/icons/compliance/{framework}.svg` + registration in `IconCompliance.tsx`

### Tests
- **Output formatter tests:** `tests/lib/outputs/compliance/{framework}/{framework}_{provider}_test.py`
- **Shared fixtures:** `tests/lib/outputs/compliance/fixtures.py`

## Resources

- **JSON Templates:** See [assets/](assets/) for framework JSON templates (cis, ens, iso27001, mitre_attack, prowler_threatscore, generic)
- **Reusable audit tooling** (added April 2026 after the FINOS CCC v2025.10 sync):
  - [assets/sync_ccc_template.py](assets/sync_ccc_template.py) — upstream YAML → Prowler JSON generator. Handles multiple upstream shapes, foreign-prefix AR rewriting, genuine collision renumbering, check mapping preservation by id or (Section, Applicability).
  - [assets/audit_framework_template.py](assets/audit_framework_template.py) — explicit REPLACE decision ledger with pre-validation against the per-provider inventory. Drop-in template for auditing any framework.
  - [assets/query_checks.py](assets/query_checks.py) — keyword/service/id query helper over `/tmp/checks_{provider}.json`.
  - [assets/dump_section.py](assets/dump_section.py) — dumps every AR for a given id prefix across all 3 providers with current check mappings.
  - [assets/build_inventory.py](assets/build_inventory.py) — generates `/tmp/checks_{provider}.json` from `*.metadata.json` files.
- **Documentation:** See [references/compliance-docs.md](references/compliance-docs.md) for additional resources
- **Related skill:** [prowler-compliance-review](../prowler-compliance-review/SKILL.md) — PR review checklist and validator script for compliance framework PRs
