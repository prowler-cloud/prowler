# Compliance Framework Documentation

## Code References

Key files for understanding and modifying compliance frameworks:

| File | Purpose |
|------|---------|
| `prowler/lib/check/compliance_models.py` | Pydantic models defining attribute structures for each framework type |
| `prowler/lib/check/compliance.py` | Core compliance processing logic |
| `prowler/lib/check/utils.py` | Utility functions including `list_compliance_modules()` |
| `prowler/lib/outputs/compliance/` | Framework-specific output generators |
| `prowler/compliance/{provider}/` | JSON compliance framework definitions |

## Attribute Model Classes

Each framework type has a specific Pydantic model in `compliance_models.py`:

| Framework | Model Class |
|-----------|-------------|
| CIS | `CIS_Requirement_Attribute` |
| ISO 27001 | `ISO27001_2013_Requirement_Attribute` |
| ENS | `ENS_Requirement_Attribute` |
| MITRE ATT&CK | `Mitre_Requirement` (uses different structure) |
| AWS Well-Architected | `AWS_Well_Architected_Requirement_Attribute` |
| KISA ISMS-P | `KISA_ISMSP_Requirement_Attribute` |
| Prowler ThreatScore | `Prowler_ThreatScore_Requirement_Attribute` |
| CCC | `CCC_Requirement_Attribute` |
| C5 Germany | `C5Germany_Requirement_Attribute` |
| Generic/Fallback | `Generic_Compliance_Requirement_Attribute` |

## How Compliance Frameworks are Loaded

1. `Compliance.get_bulk(provider)` is called at startup
2. Scans `prowler/compliance/{provider}/` for `.json` files
3. Each file is parsed using `load_compliance_framework()`
4. Pydantic validates against `Compliance` model
5. Framework is stored in dictionary with filename (without `.json`) as key

## How Checks Map to Compliance

1. After loading, `update_checks_metadata_with_compliance()` is called
2. For each check, it finds all compliance requirements that reference it
3. Compliance info is attached to `CheckMetadata.Compliance` list
4. During output, `get_check_compliance()` retrieves mappings per finding

## File Naming Convention

```
{framework}_{version}_{provider}.json
```

Examples:
- `cis_5.0_aws.json`
- `iso27001_2022_azure.json`
- `mitre_attack_gcp.json`
- `ens_rd2022_aws.json`
- `nist_800_53_revision_5_aws.json`

## Validation

Prowler validates compliance JSON at startup. Invalid files cause:
- `ValidationError` logged with details
- Application exit with error code

Common validation errors:
- Missing required fields (`Id`, `Description`, `Checks`, `Attributes`)
- Invalid enum values (e.g., `Profile` must be "Level 1" or "Level 2" for CIS)
- Type mismatches (e.g., `Checks` must be array of strings)

## Adding a New Framework

1. Create JSON file in `prowler/compliance/{provider}/`
2. Use appropriate attribute model (see table above)
3. Map existing checks to requirements via `Checks` array
4. Use empty `Checks: []` for manual-only requirements
5. Test with `prowler {provider} --list-compliance` to verify loading
6. Run `prowler {provider} --compliance {framework_name}` to test execution

## Templates

See `assets/` directory for example templates:
- `cis_framework.json` - CIS Benchmark template
- `iso27001_framework.json` - ISO 27001 template
- `ens_framework.json` - ENS (Spain) template
- `mitre_attack_framework.json` - MITRE ATT&CK template
- `prowler_threatscore_framework.json` - Prowler ThreatScore template
- `generic_framework.json` - Generic/custom framework template

## Prowler ThreatScore Details

Prowler ThreatScore is a custom security scoring framework that calculates an overall security posture score based on:

### Four Pillars
1. **IAM (Identity and Access Management)**
   - SubSections: Authentication, Authorization, Credentials Management

2. **Attack Surface**
   - SubSections: Network Exposure, Storage Exposure, Service Exposure

3. **Logging and Monitoring**
   - SubSections: Audit Logging, Threat Detection, Alerting

4. **Encryption**
   - SubSections: Data at Rest, Data in Transit

### Scoring Algorithm
The ThreatScore uses `LevelOfRisk` and `Weight` to calculate severity:

| LevelOfRisk | Weight | Example Controls |
|-------------|--------|------------------|
| 5 (Critical) | 1000 | Root MFA, No root access keys, Public S3 buckets |
| 4 (High) | 100 | User MFA, Public EC2, GuardDuty enabled |
| 3 (Medium) | 10 | Password policies, EBS encryption, CloudTrail |
| 2 (Low) | 1-10 | Best practice recommendations |
| 1 (Info) | 1 | Informational controls |

### ID Numbering Convention
- `1.x.x` - IAM controls
- `2.x.x` - Attack Surface controls
- `3.x.x` - Logging and Monitoring controls
- `4.x.x` - Encryption controls

## External Resources

### Official Framework Documentation
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [ISO 27001:2022](https://www.iso.org/standard/27001)
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST CSF](https://www.nist.gov/cyberframework)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ENS (Spain)](https://www.ccn-cert.cni.es/es/ens.html)

### Prowler Documentation
- [Prowler Docs - Compliance](https://docs.prowler.com/projects/prowler-open-source/en/latest/)
- [Prowler GitHub](https://github.com/prowler-cloud/prowler)
