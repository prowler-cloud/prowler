# Reporting

By default, Prowler will generate a CSV, JSON-OSCF, JSON-OCSF and a HTML report, however you could generate a JSON-ASFF (used by AWS Security Hub) report with `-M` or `--output-modes`:

```console
prowler <provider> -M csv json-ocsf json-asff
```

By default, all compliance outputs will be generated when Prowler is executed. Compliance outputs will be placed inside `/output/compliance` directory.

## Custom Output Flags
By default, Prowler creates a file inside the `output` directory named `prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format`.

However, both the output file name and directory can be personalised:

- Custom output report name: you can use the flag `-F`/`--output-filename`
```console
prowler <provider> -M csv json-ocsf json-asff -F <custom_report_name>
```
- Custom output directory: you can use the flag `-o`/`--output-directory`
```console
prowler <provider> -M csv json-ocsf json-asff -o <custom_report_directory>
```
???+ note
    Both flags can be used simultaneously to provide a custom directory and filename.
    ```console
    prowler <provider> -M csv json-ocsf json-asff \
            -F <custom_report_name> -o <custom_report_directory>
    ```
## Output timestamp format
By default, the timestamp format of the output files is ISO 8601. This can be changed with the flag `--unix-timestamp` generating the timestamp fields in pure unix timestamp format.

## Output Formats

Prowler supports natively the following output formats:

- CSV
- JSON-OCSF
- JSON-ASFF

Hereunder is the structure for each of the supported report formats by Prowler:

### CSV

CSV format has a set of common columns for all the providers.
The common columns are the following:

- AUTH_METHOD
- TIMESTAMP
- ACCOUNT_UID
- ACCOUNT_NAME
- ACCOUNT_EMAIL
- ACCOUNT_ORGANIZATION_UID
- ACCOUNT_ORGANIZATION_NAME
- ACCOUNT_TAGS
- FINDING_UID
- PROVIDER
- CHECK_ID
- CHECK_TITLE
- CHECK_TYPE
- STATUS
- STATUS_EXTENDED
- MUTED
- SERVICE_NAME
- SUBSERVICE_NAME
- SEVERITY
- RESOURCE_TYPE
- RESOURCE_UID
- RESOURCE_NAME
- RESOURCE_DETAILS
- RESOURCE_TAGS
- PARTITION
- REGION
- DESCRIPTION
- RISK
- RELATED_URL
- REMEDIATION_RECOMMENDATION_TEXT
- REMEDIATION_RECOMMENDATION_URL
- REMEDIATION_CODE_NATIVEIAC
- REMEDIATION_CODE_TERRAFORM
- REMEDIATION_CODE_CLI
- REMEDIATION_CODE_OTHER
- COMPLIANCE
- CATEGORIES
- DEPENDS_ON
- RELATED_TO
- NOTES
- PROWLER_VERSION

???+ note
    Since Prowler v4 the CSV column delimiter is the semicolon (`;`)

In the previous Prowler version, each provider had some columns different from the rest. These are the cases that have changed:

- AWS

    | V3 | V4 |
    |---|---|
    | profile | auth_method |
    | account_id| account_uid |
    | account_organization_arn | account_organization_uid |
    | account_org | account_organization_name |
    | resource_id | resource_name |
    | resource_arn | resource_uid |
    | finding_unique_id | finding_uid |
    | assessment_start_time | timestamp |

- AZURE

    | V3 | V4 |
    |---|---|
    | tenant_domain | account_organization_name |
    | subscription | account_uid |
    | resource_id | resource_name |
    | resource_arn | resource_uid |

- GCP
    | V3 | V4 |
    |---|---|
    | project_id | account_uid |
    | location | region |
    | resource_id | resource_name |
    | resource_arn | resource_uid |


### JSON-OCSF

Based on [Open Cybersecurity Schema Framework Security Finding v1.1.0](https://schema.ocsf.io/1.1.0/classes/detection_finding?extensions=)

```json
[{
    "finding": {
        "title": "Check if ACM Certificates are about to expire in specific days or less",
        "desc": "Check if ACM Certificates are about to expire in specific days or less",
        "supporting_data": {
            "Risk": "Expired certificates can impact service availability.",
            "Notes": ""
        },
        "remediation": {
            "kb_articles": [
                "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html"
            ],
            "desc": "Monitor certificate expiration and take automated action to renew; replace or remove. Having shorter TTL for any security artifact is a general recommendation; but requires additional automation in place. If not longer required delete certificate. Use AWS config using the managed rule: acm-certificate-expiration-check."
        },
        "types": [
            "Data Protection"
        ],
        "src_url": "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html",
        "uid": "prowler-aws-acm_certificates_expiration_check-012345678912-eu-west-1-*.xxxxxxxxxxxxxx",
        "related_events": []
    },
    "resources": [
        {
            "group": {
                "name": "acm"
            },
            "region": "eu-west-1",
            "name": "xxxxxxxxxxxxxx",
            "uid": "arn:aws:acm:eu-west-1:012345678912:certificate/xxxxxxxxxxxxxx",
            "labels": [
                {
                    "Key": "project",
                    "Value": "prowler-pro"
                },
                {
                    "Key": "environment",
                    "Value": "dev"
                },
                {
                    "Key": "terraform",
                    "Value": "true"
                },
                {
                    "Key": "terraform_state",
                    "Value": "aws"
                }
            ],
            "type": "AwsCertificateManagerCertificate",
            "details": ""
        }
    ],
    "status_detail": "ACM Certificate for xxxxxxxxxxxxxx expires in 111 days.",
    "compliance": {
        "status": "Success",
        "requirements": [
            "CISA: ['your-data-2']",
            "SOC2: ['cc_6_7']",
            "MITRE-ATTACK: ['T1040']",
            "GDPR: ['article_32']",
            "HIPAA: ['164_308_a_4_ii_a', '164_312_e_1']",
            "AWS-Well-Architected-Framework-Security-Pillar: ['SEC09-BP01']",
            "NIST-800-171-Revision-2: ['3_13_1', '3_13_2', '3_13_8', '3_13_11']",
            "NIST-800-53-Revision-4: ['ac_4', 'ac_17_2', 'sc_12']",
            "NIST-800-53-Revision-5: ['sc_7_12', 'sc_7_16']",
            "NIST-CSF-1.1: ['ac_5', 'ds_2']",
            "RBI-Cyber-Security-Framework: ['annex_i_1_3']",
            "FFIEC: ['d3-pc-im-b-1']",
            "FedRamp-Moderate-Revision-4: ['ac-4', 'ac-17-2', 'sc-12']",
            "FedRAMP-Low-Revision-4: ['ac-17', 'sc-12']"
        ],
        "status_detail": "ACM Certificate for xxxxxxxxxxxxxx expires in 111 days."
    },
    "message": "ACM Certificate for xxxxxxxxxxxxxx expires in 111 days.",
    "severity_id": 4,
    "severity": "High",
    "cloud": {
        "account": {
            "name": "",
            "uid": "012345678912"
        },
        "region": "eu-west-1",
        "org": {
            "uid": "",
            "name": ""
        },
        "provider": "aws",
        "project_uid": ""
    },
    "time": "2023-06-30 10:28:55.297615",
    "metadata": {
        "original_time": "2023-06-30T10:28:55.297615",
        "profiles": [
            "dev"
        ],
        "product": {
            "language": "en",
            "name": "Prowler",
            "version": "3.6.1",
            "vendor_name": "Prowler/ProwlerPro",
            "feature": {
                "name": "acm_certificates_expiration_check",
                "uid": "acm_certificates_expiration_check",
                "version": "3.6.1"
            }
        },
        "version": "1.0.0-rc.3"
    },
    "state_id": 0,
    "state": "New",
    "status_id": 1,
    "status": "Success",
    "type_uid": 200101,
    "type_name": "Security Finding: Create",
    "impact_id": 0,
    "impact": "Unknown",
    "confidence_id": 0,
    "confidence": "Unknown",
    "activity_id": 1,
    "activity_name": "Create",
    "category_uid": 2,
    "category_name": "Findings",
    "class_uid": 2001,
    "class_name": "Security Finding"
},{
    "finding": {
        "title": "Check if ACM Certificates are about to expire in specific days or less",
        "desc": "Check if ACM Certificates are about to expire in specific days or less",
        "supporting_data": {
            "Risk": "Expired certificates can impact service availability.",
            "Notes": ""
        },
        "remediation": {
            "kb_articles": [
                "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html"
            ],
            "desc": "Monitor certificate expiration and take automated action to renew; replace or remove. Having shorter TTL for any security artifact is a general recommendation; but requires additional automation in place. If not longer required delete certificate. Use AWS config using the managed rule: acm-certificate-expiration-check."
        },
        "types": [
            "Data Protection"
        ],
        "src_url": "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html",
        "uid": "prowler-aws-acm_certificates_expiration_check-012345678912-eu-west-1-xxxxxxxxxxxxx",
        "related_events": []
    },
    "resources": [
        {
            "group": {
                "name": "acm"
            },
            "region": "eu-west-1",
            "name": "xxxxxxxxxxxxx",
            "uid": "arn:aws:acm:eu-west-1:012345678912:certificate/3ea965a0-368d-4d13-95eb-5042a994edc4",
            "labels": [
                {
                    "Key": "name",
                    "Value": "prowler-pro-saas-dev-acm-internal-wildcard"
                },
                {
                    "Key": "project",
                    "Value": "prowler-pro-saas"
                },
                {
                    "Key": "environment",
                    "Value": "dev"
                },
                {
                    "Key": "terraform",
                    "Value": "true"
                },
                {
                    "Key": "terraform_state",
                    "Value": "aws/saas/base"
                }
            ],
            "type": "AwsCertificateManagerCertificate",
            "details": ""
        }
    ],
    "status_detail": "ACM Certificate for xxxxxxxxxxxxx expires in 119 days.",
    "compliance": {
        "status": "Success",
        "requirements": [
            "CISA: ['your-data-2']",
            "SOC2: ['cc_6_7']",
            "MITRE-ATTACK: ['T1040']",
            "GDPR: ['article_32']",
            "HIPAA: ['164_308_a_4_ii_a', '164_312_e_1']",
            "AWS-Well-Architected-Framework-Security-Pillar: ['SEC09-BP01']",
            "NIST-800-171-Revision-2: ['3_13_1', '3_13_2', '3_13_8', '3_13_11']",
            "NIST-800-53-Revision-4: ['ac_4', 'ac_17_2', 'sc_12']",
            "NIST-800-53-Revision-5: ['sc_7_12', 'sc_7_16']",
            "NIST-CSF-1.1: ['ac_5', 'ds_2']",
            "RBI-Cyber-Security-Framework: ['annex_i_1_3']",
            "FFIEC: ['d3-pc-im-b-1']",
            "FedRamp-Moderate-Revision-4: ['ac-4', 'ac-17-2', 'sc-12']",
            "FedRAMP-Low-Revision-4: ['ac-17', 'sc-12']"
        ],
        "status_detail": "ACM Certificate for xxxxxxxxxxxxx expires in 119 days."
    },
    "message": "ACM Certificate for xxxxxxxxxxxxx expires in 119 days.",
    "severity_id": 4,
    "severity": "High",
    "cloud": {
        "account": {
            "name": "",
            "uid": "012345678912"
        },
        "region": "eu-west-1",
        "org": {
            "uid": "",
            "name": ""
        },
        "provider": "aws",
        "project_uid": ""
    },
    "time": "2023-06-30 10:28:55.297615",
    "metadata": {
        "original_time": "2023-06-30T10:28:55.297615",
        "profiles": [
            "dev"
        ],
        "product": {
            "language": "en",
            "name": "Prowler",
            "version": "3.6.1",
            "vendor_name": "Prowler/ProwlerPro",
            "feature": {
                "name": "acm_certificates_expiration_check",
                "uid": "acm_certificates_expiration_check",
                "version": "3.6.1"
            }
        },
        "version": "1.0.0-rc.3"
    },
    "state_id": 0,
    "state": "New",
    "status_id": 1,
    "status": "Success",
    "type_uid": 200101,
    "type_name": "Security Finding: Create",
    "impact_id": 0,
    "impact": "Unknown",
    "confidence_id": 0,
    "confidence": "Unknown",
    "activity_id": 1,
    "activity_name": "Create",
    "category_uid": 2,
    "category_name": "Findings",
    "class_uid": 2001,
    "class_name": "Security Finding"
}]
```

???+ note
    Each finding is a `json` object.

### JSON-ASFF

???+ note
    Only available when using Security Hub option

The following code is an example output of the [JSON-ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html) format:

```json
[{
    "SchemaVersion": "2018-10-08",
    "Id": "prowler-rds_instance_minor_version_upgrade_enabled-ACCOUNT_ID-eu-west-1-b1ade474a",
    "ProductArn": "arn:aws:securityhub:eu-west-1::product/prowler/prowler",
    "RecordState": "ACTIVE",
    "ProductFields": {
        "ProviderName": "Prowler",
        "ProviderVersion": "3.0-beta-21Nov2022",
        "ProwlerResourceName": "rds-instance-id"
    },
    "GeneratorId": "prowler-rds_instance_minor_version_upgrade_enabled",
    "AwsAccountId": "ACCOUNT_ID",
    "Types": [],
    "FirstObservedAt": "2022-12-01T13:16:57Z",
    "UpdatedAt": "2022-12-01T13:16:57Z",
    "CreatedAt": "2022-12-01T13:16:57Z",
    "Severity": {
        "Label": "LOW"
    },
    "Title": "Ensure RDS instances have minor version upgrade enabled.",
    "Description": "Ensure RDS instances have minor version upgrade enabled.",
    "Resources": [
        {
            "Type": "AwsRdsDbInstance",
            "Id": "rds-instance-id",
            "Partition": "aws",
            "Region": "eu-west-1"
        }
    ],
    "Compliance": {
        "Status": "PASSED",
        "RelatedRequirements": [
            "CISA your-systems-2 booting-up-thing-to-do-first-3",
            "CIS-1.5 2.3.2",
            "AWS-Foundational-Security-Best-Practices rds",
            "RBI-Cyber-Security-Framework annex_i_6",
            "FFIEC d3-cc-pm-b-1 d3-cc-pm-b-3"
        ],
        "AssociatedStandards": [
            {
                "StandardsId": "CISA"
            },
            {
                "StandardsId": "CIS-1.5"
            },
            {
                "StandardsId": "AWS-Foundational-Security-Best-Practices"
            },
            {
                "StandardsId": "RBI-Cyber-Security-Framework"
            },
            {
                "StandardsId": "FFIEC"
            }
        ]
    },
    "Remediation": {
        "Recommendation": {
            "Text": "Enable auto minor version upgrade for all databases and environments.",
            "Url": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/"
        }
    }
},{
    "SchemaVersion": "2018-10-08",
    "Id": "prowler-rds_instance_minor_version_upgrade_enabled-ACCOUNT_ID-eu-west-1-06d21d75e",
    "ProductArn": "arn:aws:securityhub:eu-west-1::product/prowler/prowler",
    "RecordState": "ACTIVE",
    "ProductFields": {
        "ProviderName": "Prowler",
        "ProviderVersion": "3.0-beta-21Nov2022",
        "ProwlerResourceName": "rds-instance-id"
    },
    "GeneratorId": "prowler-rds_instance_minor_version_upgrade_enabled",
    "AwsAccountId": "ACCOUNT_ID",
    "Types": [],
    "FirstObservedAt": "2022-12-01T13:16:57Z",
    "UpdatedAt": "2022-12-01T13:16:57Z",
    "CreatedAt": "2022-12-01T13:16:57Z",
    "Severity": {
        "Label": "LOW"
    },
    "Title": "Ensure RDS instances have minor version upgrade enabled.",
    "Description": "Ensure RDS instances have minor version upgrade enabled.",
    "Resources": [
        {
            "Type": "AwsRdsDbInstance",
            "Id": "rds-instance-id",
            "Partition": "aws",
            "Region": "eu-west-1"
        }
    ],
    "Compliance": {
        "Status": "PASSED",
        "RelatedRequirements": [
            "CISA your-systems-2 booting-up-thing-to-do-first-3",
            "CIS-1.5 2.3.2",
            "AWS-Foundational-Security-Best-Practices rds",
            "RBI-Cyber-Security-Framework annex_i_6",
            "FFIEC d3-cc-pm-b-1 d3-cc-pm-b-3"
        ],
        "AssociatedStandards": [
            {
                "StandardsId": "CISA"
            },
            {
                "StandardsId": "CIS-1.5"
            },
            {
                "StandardsId": "AWS-Foundational-Security-Best-Practices"
            },
            {
                "StandardsId": "RBI-Cyber-Security-Framework"
            },
            {
                "StandardsId": "FFIEC"
            }
        ]
    },
    "Remediation": {
        "Recommendation": {
            "Text": "Enable auto minor version upgrade for all databases and environments.",
            "Url": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/"
        }
    }
}]
```

???+ note
    Each finding is a `json` object within a list.


## V4 Deprecations

Some deprecations have been made to unify formats and improve outputs

### HTML

HTML output format has been deprecated

### JSON

JSON format has been deprecated since new JSON output is JSON OSCF v1.1.08 (for Security Hub option the JSON format is JSON ASFF)
