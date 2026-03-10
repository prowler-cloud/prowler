---
name: prowler-compliance
description: >
  Creates and manages Prowler compliance frameworks.
  Trigger: When working with compliance frameworks (CIS, NIST, PCI-DSS, SOC2, GDPR, ISO27001, ENS, MITRE ATT&CK).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, sdk]
  auto_invoke:
    - "Creating/updating compliance frameworks"
    - "Mapping checks to compliance controls"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

Use this skill when:
- Creating a new compliance framework for any provider
- Adding requirements to existing frameworks
- Mapping checks to compliance controls
- Understanding compliance framework structures and attributes

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

## Best Practices

1. **Requirement IDs**: Follow the original framework numbering exactly (e.g., "1.1", "A.5.1", "T1190", "ac_2_1")
2. **Check Mapping**: Map to existing checks when possible. Use `Checks: []` for manual-only requirements
3. **Completeness**: Include all framework requirements, even those without automated checks
4. **Version Control**: Include framework version in `Name` and `Version` fields
5. **File Naming**: Use format `{framework}_{version}_{provider}.json`
6. **Validation**: Prowler validates JSON against Pydantic models at startup - invalid JSON will cause errors

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

- **Compliance Models:** `prowler/lib/check/compliance_models.py`
- **Compliance Processing:** `prowler/lib/check/compliance.py`
- **Compliance Output:** `prowler/lib/outputs/compliance/`

## Resources

- **Templates:** See [assets/](assets/) for framework JSON templates
- **Documentation:** See [references/compliance-docs.md](references/compliance-docs.md) for additional resources
