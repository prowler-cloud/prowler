# Reporting

By default, Prowler will generate a CSV, JSON and a HTML report, however you could generate a JSON-ASFF (used by AWS Security Hub) report with `-M` or `--output-modes`:

```console
prowler <provider> -M csv json json-asff html
```

## Custom Output Flags
By default, Prowler creates a file inside the `output` directory named `prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format`.

However, both the output file name and directory can be personalised:

- Custom output report name: you can use the flag `-F`/`--output-filename`
```console
prowler <provider> -M csv json json-asff html -F <custom_report_name>
```
- Custom output directory: you can use the flag `-o`/`--output-directory`
```console
prowler <provider> -M csv json json-asff html -o <custom_report_directory>
```
> Both flags can be used simultainously to provide a custom directory and filename.
```console
prowler <provider> -M csv json json-asff html -F <custom_report_name> -o <custom_report_directory>
```
## Send report to AWS S3 Bucket

To save your report in an S3 bucket, use `-B`/`--output-bucket` to define a custom output bucket along with `-M` to define the output format that is going to be uploaded to S3:

```sh
prowler <provider> -M csv -B my-bucket/folder/
```

> In the case you do not want to use the assumed role credentials but the initial credentials to put the reports into the S3 bucket, use `-D`/`--output-bucket-no-assume` instead of `-B`/`--output-bucket.

> Make sure that the used credentials have s3:PutObject permissions in the S3 path where the reports are going to be uploaded.

## Output Formats

Prowler supports natively the following output formats:

- CSV
- JSON
- JSON-ASFF
- HTML

Hereunder is the structure for each of the supported report formats by Prowler:

### HTML
![HTML Output](../img/output-html.png)
### CSV
| ASSESSMENT_START_TIME | FINDING_UNIQUE_ID | PROVIDER | PROFILE | ACCOUNT_ID | ACCOUNT_NAME | ACCOUNT_EMAIL | ACCOUNT_ARN | ACCOUNT_ORG | ACCOUNT_TAGS | REGION | CHECK_ID | CHECK_TITLE | CHECK_TYPE | STATUS | STATUS_EXTENDED | SERVICE_NAME | SUBSERVICE_NAME | SEVERITY | RESOURCE_ID | RESOURCE_ARN | RESOURCE_TYPE | RESOURCE_DETAILS | RESOURCE_TAGS | DESCRIPTION | COMPLIANCE | RISK | RELATED_URL | REMEDIATION_RECOMMENDATION_TEXT | REMEDIATION_RECOMMENDATION_URL | REMEDIATION_RECOMMENDATION_CODE_NATIVEIAC | REMEDIATION_RECOMMENDATION_CODE_TERRAFORM | REMEDIATION_RECOMMENDATION_CODE_CLI | REMEDIATION_RECOMMENDATION_CODE_OTHER | CATEGORIES | DEPENDS_ON | RELATED_TO | NOTES |
| ------- | ----------- | ------ | -------- | ------------ | ----------- | ---------- | ---------- | --------------------- | -------------------------- | -------------- | ----------------- | ------------------------ | --------------- | ---------- | ----------------- | --------- | -------------- | ----------------- | ------------------ | --------------------- | -------------------- | ------------------- | ------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- |

### JSON

```
[{
    "AssessmentStartTime": "2022-12-01T14:16:57.354413",
    "FindingUniqueId": "",
    "Provider": "aws",
    "Profile": "dev",
    "AccountId": "ACCOUNT_ID",
    "OrganizationsInfo": null,
    "Region": "eu-west-1",
    "CheckID": "rds_instance_minor_version_upgrade_enabled",
    "CheckTitle": "Ensure RDS instances have minor version upgrade enabled.",
    "CheckType": [],
    "ServiceName": "rds",
    "SubServiceName": "",
    "Status": "PASS",
    "StatusExtended": "RDS Instance rds-instance-id has minor version upgrade enabled.",
    "Severity": "low",
    "ResourceId": "rds-instance-id",
    "ResourceArn": "",
    "ResourceTags": {
        "test": "test",
        "enironment": "dev"
    },
    "ResourceType": "AwsRdsDbInstance",
    "ResourceDetails": "",
    "Description": "Ensure RDS instances have minor version upgrade enabled.",
    "Risk": "Auto Minor Version Upgrade is a feature that you can enable to have your database automatically upgraded when a new minor database engine version is available. Minor version upgrades often patch security vulnerabilities and fix bugs and therefore should be applied.",
    "RelatedUrl": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/",
    "Remediation": {
        "Code": {
            "NativeIaC": "https://docs.bridgecrew.io/docs/ensure-aws-db-instance-gets-all-minor-upgrades-automatically#cloudformation",
            "Terraform": "https://docs.bridgecrew.io/docs/ensure-aws-db-instance-gets-all-minor-upgrades-automatically#terraform",
            "CLI": "aws rds modify-db-instance --db-instance-identifier <db_instance_id> --auto-minor-version-upgrade --apply-immediately",
            "Other": "https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/RDS/rds-auto-minor-version-upgrade.html"
        },
        "Recommendation": {
            "Text": "Enable auto minor version upgrade for all databases and environments.",
            "Url": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/"
        }
    },
    "Categories": [],
    "Notes": "",
    "Compliance": {
        "CIS-1.4": [
            "1.20"
        ],
        "CIS-1.5": [
            "1.20"
        ]
    }
},{
    "AssessmentStartTime": "2022-12-01T14:16:57.354413",
    "FindingUniqueId": "",
    "Provider": "aws",
    "Profile": "dev",
    "AccountId": "ACCOUNT_ID",
    "OrganizationsInfo": null,
    "Region": "eu-west-1",
    "CheckID": "rds_instance_minor_version_upgrade_enabled",
    "CheckTitle": "Ensure RDS instances have minor version upgrade enabled.",
    "CheckType": [],
    "ServiceName": "rds",
    "SubServiceName": "",
    "Status": "PASS",
    "StatusExtended": "RDS Instance rds-instance-id has minor version upgrade enabled.",
    "Severity": "low",
    "ResourceId": "rds-instance-id",
    "ResourceArn": "",
    "ResourceType": "AwsRdsDbInstance",
    "ResourceTags": {},
    "Description": "Ensure RDS instances have minor version upgrade enabled.",
    "Risk": "Auto Minor Version Upgrade is a feature that you can enable to have your database automatically upgraded when a new minor database engine version is available. Minor version upgrades often patch security vulnerabilities and fix bugs and therefore should be applied.",
    "RelatedUrl": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/",
    "Remediation": {
        "Code": {
            "NativeIaC": "https://docs.bridgecrew.io/docs/ensure-aws-db-instance-gets-all-minor-upgrades-automatically#cloudformation",
            "Terraform": "https://docs.bridgecrew.io/docs/ensure-aws-db-instance-gets-all-minor-upgrades-automatically#terraform",
            "CLI": "aws rds modify-db-instance --db-instance-identifier <db_instance_id> --auto-minor-version-upgrade --apply-immediately",
            "Other": "https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/RDS/rds-auto-minor-version-upgrade.html"
        },
        "Recommendation": {
            "Text": "Enable auto minor version upgrade for all databases and environments.",
            "Url": "https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/"
        }
    },
    "Categories": [],
    "Notes": "",
    "Compliance: {}
}]
```

> NOTE: Each finding is a `json` object.

### JSON-ASFF

```
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

> NOTE: Each finding is a `json` object.
