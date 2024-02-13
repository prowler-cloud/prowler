# Compliance
Prowler allows you to execute checks based on requirements defined in compliance frameworks.

## List Available Compliance Frameworks
In order to see which compliance frameworks are cover by Prowler, you can use option `--list-compliance`:
```sh
prowler <provider> --list-compliance
```
Currently, the available frameworks are:
- `aws_account_security_onboarding_aws`
- `aws_audit_manager_control_tower_guardrails_aws`
- `aws_foundational_security_best_practices_aws`
- `aws_well_architected_framework_reliability_pillar_aws`
- `aws_well_architected_framework_security_pillar_aws`
- `cis_1.4_aws`
- `cis_1.5_aws`
- `cis_2.0_aws`
- `cis_2.0_gcp`
- `cis_3.0_aws`
- `cisa_aws`
- `ens_rd2022_aws`
- `fedramp_low_revision_4_aws`
- `fedramp_moderate_revision_4_aws`
- `ffiec_aws`
- `gdpr_aws`
- `gxp_21_cfr_part_11_aws`
- `gxp_eu_annex_11_aws`
- `hipaa_aws`
- `iso27001_2013_aws`
- `mitre_attack_aws`
- `nist_800_171_revision_2_aws`
- `nist_800_53_revision_4_aws`
- `nist_800_53_revision_5_aws`
- `nist_csf_1.1_aws`
- `pci_3.2.1_aws`
- `rbi_cyber_security_framework_aws`
- `soc2_aws`

## List Requirements of Compliance Frameworks
For each compliance framework, you can use option `--list-compliance-requirements` to list its requirements:
```sh
prowler <provider> --list-compliance-requirements <compliance_framework(s)>
```

Example for the first requirements of CIS 1.5 for AWS:

```
Listing CIS 1.5 AWS Compliance Requirements:

Requirement Id: 1.1
	- Description: Maintain current contact details
	- Checks:
 		account_maintain_current_contact_details

Requirement Id: 1.2
	- Description: Ensure security contact information is registered
	- Checks:
 		account_security_contact_information_is_registered

Requirement Id: 1.3
	- Description: Ensure security questions are registered in the AWS account
	- Checks:
 		account_security_questions_are_registered_in_the_aws_account

Requirement Id: 1.4
	- Description: Ensure no 'root' user account access key exists
	- Checks:
 		iam_no_root_access_key

Requirement Id: 1.5
	- Description: Ensure MFA is enabled for the 'root' user account
	- Checks:
 		iam_root_mfa_enabled

[redacted]

```

## Execute Prowler based on Compliance Frameworks
As we mentioned, Prowler can be execute to analyse you environment based on a specific compliance framework, to do it, you can use option `--compliance`:
```sh
prowler <provider> --compliance <compliance_framework>
```
Standard results will be shown and additionally the framework information as the sample below for CIS AWS 1.5. For details a CSV file has been generated as well.

<img src="../img/compliance-cis-sample1.png"/>

## Create and contribute adding other Security Frameworks

This information is part of the Developer Guide and can be found here: https://docs.prowler.cloud/en/latest/tutorials/developer-guide/.
