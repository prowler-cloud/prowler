# Reporting

By default, Prowler will generate the CSV and JSON-OCSF report. If you want to generate the JSON-ASFF (used by AWS Security Hub) report you can set it using the `-M/--output-modes/--output-formats`, like: `prowler --output-formats json-asff`.

```console
prowler <provider> -M csv json-ocsf json-asff
```

By default, all the compliance outputs will be generated when Prowler is executed. Compliance outputs will be placed inside the `/output/compliance` directory.

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

The CSV format has a common format for all the providers. The following are the available columns:

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
    Since Prowler v3 the CSV column delimiter is the semicolon (`;`)


### JSON-OCSF

Based on [Open Cybersecurity Schema Framework Security Finding v1.1.0](https://schema.ocsf.io/1.1.0/classes/detection_finding?extensions=)

```json
[{
    "metadata": {
        "product": {
            "name": "Prowler",
            "vendor_name": "Prowler",
            "version": "4.0.0"
        },
        "version": "1.1.0"
    },
    "severity_id": 4,
    "severity": "High",
    "status": "New",
    "status_code": "FAIL",
    "status_detail": "No CloudTrail trails enabled and logging were found.",
    "status_id": 1,
    "activity_name": "Create",
    "activity_id": 1,
    "finding_info": {
        "created_time": "2024-04-08T11:33:51.870861",
        "desc": "Ensure CloudTrail is enabled in all regions",
        "product_uid": "prowler",
        "title": "Ensure CloudTrail is enabled in all regions",
        "uid": "prowler-aws-cloudtrail_multi_region_enabled-xxxxxxxx-ap-northeast-1-xxxxxxxx"
    },
    "resources": [
        {
            "cloud_partition": "aws",
            "region": "ap-northeast-1",
            "group": {
                "name": "cloudtrail"
            },
            "labels": [],
            "name": "xxxxxxxx",
            "type": "AwsCloudTrailTrail",
            "uid": "arn:aws:cloudtrail:ap-northeast-1:xxxxxxxx:trail"
        }
    ],
    "category_name": "Findings",
    "category_uid": 2,
    "class_name": "DetectionFinding",
    "class_uid": 2004,
    "cloud": {
        "account": {
            "name": "",
            "type": "AWS_Account",
            "type_id": 10,
            "uid": "xxxxxxxx"
        },
        "org": {
            "name": "",
            "uid": ""
        },
        "provider": "aws",
        "region": "ap-northeast-1"
    },
    "event_time": "2024-04-08T11:33:51.870861",
    "remediation": {
        "desc": "Ensure Logging is set to ON on all regions (even if they are not being used at the moment.",
        "references": [
            "aws cloudtrail create-trail --name <trail_name> --bucket-name <s3_bucket_for_cloudtrail> --is-multi-region-trail aws cloudtrail update-trail --name <trail_name> --is-multi-region-trail ",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrailconcepts.html#cloudtrail-concepts-management-events"
        ]
    },
    "type_uid": 200401,
    "type_name": "Create"
},{
    "metadata": {
        "product": {
            "name": "Prowler",
            "vendor_name": "Prowler",
            "version": "4.0.0"
        },
        "version": "1.1.0"
    },
    "severity_id": 4,
    "severity": "High",
    "status": "New",
    "status_code": "FAIL",
    "status_detail": "No CloudTrail trails enabled and logging were found.",
    "status_id": 1,
    "activity_name": "Create",
    "activity_id": 1,
    "finding_info": {
        "created_time": "2024-04-08T11:33:51.870861",
        "desc": "Ensure CloudTrail is enabled in all regions",
        "product_uid": "prowler",
        "title": "Ensure CloudTrail is enabled in all regions",
        "uid": "prowler-aws-cloudtrail_multi_region_enabled-xxxxxxxx-ap-northeast-2-xxxxxxxx"
    },
    "resources": [
        {
            "cloud_partition": "aws",
            "region": "ap-northeast-2",
            "group": {
                "name": "cloudtrail"
            },
            "labels": [],
            "name": "xxxxxxxx",
            "type": "AwsCloudTrailTrail",
            "uid": "arn:aws:cloudtrail:ap-northeast-2:xxxxxxxx:trail"
        }
    ],
    "category_name": "Findings",
    "category_uid": 2,
    "class_name": "DetectionFinding",
    "class_uid": 2004,
    "cloud": {
        "account": {
            "name": "",
            "type": "AWS_Account",
            "type_id": 10,
            "uid": "xxxxxxxx"
        },
        "org": {
            "name": "",
            "uid": ""
        },
        "provider": "aws",
        "region": "ap-northeast-2"
    },
    "event_time": "2024-04-08T11:33:51.870861",
    "remediation": {
        "desc": "Ensure Logging is set to ON on all regions (even if they are not being used at the moment.",
        "references": [
            "aws cloudtrail create-trail --name <trail_name> --bucket-name <s3_bucket_for_cloudtrail> --is-multi-region-trail aws cloudtrail update-trail --name <trail_name> --is-multi-region-trail ",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrailconcepts.html#cloudtrail-concepts-management-events"
        ]
    },
    "type_uid": 200401,
    "type_name": "Create"
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

Some deprecations have been made to unify formats and improve outputs.

### HTML

HTML output format has been deprecated.

### JSON

Native JSON format has been deprecated in favor of JSON [OSCF](https://schema.ocsf.io/) `v1.1.0`.

### CSV Columns

In Prowler v3 each provider had some specific columns, different from the rest. These are the cases that have changed in Prowler v4:

| Provider | V3 | V4 |
| --- |---|---|
| aws | profile | auth_method |
| aws | account_id| account_uid |
| aws | account_organization_arn | account_organization_uid |
| aws | account_org | account_organization_name |
| aws | finding_unique_id | finding_uid |
| aws | assessment_start_time | timestamp |
| azure | tenant_domain | account_organization_name |
| azure | subscription | account_uid |
| gcp | project_id | account_uid |
| gcp | location | region |
| aws / azure / gcp | resource_id | resource_name |
| aws / azure / gcp | resource_arn | resource_uid |
