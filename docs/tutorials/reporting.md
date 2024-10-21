# Reporting

By default, Prowler will generate the CSV and JSON-[OCSF](https://schema.ocsf.io/) report.

```console
prowler <provider> -M csv json-ocsf json-asff html
```

If you want to generate the JSON-ASFF (used by AWS Security Hub) report you can set it using the `-M/--output-modes/--output-formats`, like:

```console
prowler <provider> --output-formats json-asff
```

By default, all the compliance outputs will be generated when Prowler is executed. Compliance outputs will be placed inside the `/output/compliance` directory.

## Custom Output Flags
By default, Prowler creates a file inside the `output` directory named: `prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format`.

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
- HTML

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

#### CSV Headers Mapping

The following table shows the mapping between the CSV headers and the the providers fields:

| Open Source Consolidated    | AWS                         | GCP                          | AZURE                       | KUBERNETES                 |
|-----------------------------|-----------------------------|------------------------------|-----------------------------|----------------------------|
| auth_method                 | profile                     | principal                    | identity_type : identity_id | in-cluster/kube-config     |
| provider                    | provider                    | provider                     | provider                    | provider                   |
| account_uid                 | account_id / account_arn    | project_id                   | subscription_id             | cluster                    |
| account_name                | account_name                | project_name                 | subscription_name           | context:context            |
| account_email               | account_email               | N/A                          | N/A                         | N/A                        |
| account_organization_uid    | account_organizations_arn   | project_organization_id      | tenant_id                   | N/A                        |
| account_organization_name   | account_org                 | project_organization_display_name | tenant_domain          | N/A                        |
| account_tags                | account_tags                | project_labels               | subscription_tags           | N/A                        |
| partition                   | partition                   | N/A                          | region_config.name          | N/A                        |
| region                      | region                      | location                     | location                    | namespace:namespace        |
| resource_name               | resource_id                 | resource_name                | resource_name               | resource_name              |
| resource_uid                | resource_arn                | resource_id                  | resource_id                 | resource_id                |
| finding_uid                 | finding_unique_id           | finding_unique_id            | finding_unique_id           | finding_unique_id          |


### JSON-OCSF

The JSON-OCSF output format implements the [Detection Finding](https://schema.ocsf.io/1.1.0/classes/detection_finding) from the [OCSF v1.1.0](https://schema.ocsf.io/1.1.0)

```json
[{
    "metadata": {
        "event_code": "cloudtrail_multi_region_enabled",
        "product": {
            "name": "Prowler",
            "vendor_name": "Prowler",
            "version": "4.2.4"
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
        "uid": "prowler-aws-cloudtrail_multi_region_enabled-123456789012-ap-northeast-1-123456789012",
        "types": ["Software and Configuration Checks","Industry and Regulatory Standards","CIS AWS Foundations Benchmark"],
    },
    "resources": [
        {
            "cloud_partition": "aws",
            "region": "ap-northeast-1",
            "group": {
                "name": "cloudtrail"
            },
            "labels": [],
            "name": "123456789012",
            "type": "AwsCloudTrailTrail",
            "uid": "arn:aws:cloudtrail:ap-northeast-1:123456789012:trail",
            "data": {
                "details": ""
            },
        }
    ],
    "category_name": "Findings",
    "category_uid": 2,
    "class_name": "DetectionFinding",
    "class_uid": 2004,
    "cloud": {
        "account": {
            "name": "test-account",
            "type": "AWS_Account",
            "type_id": 10,
            "uid": "123456789012"
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
    "type_name": "Create",
    "unmapped": {
        "related_url": "",
        "categories": ["forensics-ready"],
        "depends_on": [],
        "related_to": [],
        "notes": "",
        "compliance": {
            "CISA": [
                "your-systems-3",
                "your-data-2"
            ],
            "SOC2": [
                "cc_2_1",
                "cc_7_2",
                "cc_a_1_2"
            ],
            "CIS-1.4": [
                "3.1"
            ],
            "CIS-1.5": [
                "3.1"
            ],
            "GDPR": [
                "article_25",
                "article_30"
            ],
            "AWS-Foundational-Security-Best-Practices": [
                "cloudtrail"
            ],
            "ISO27001-2013": [
                "A.12.4"
            ],
            "HIPAA": [
                "164_308_a_1_ii_d",
                "164_308_a_3_ii_a",
                "164_308_a_6_ii",
                "164_312_b",
                "164_312_e_2_i"
            ],
        }
    },
}]
```

???+ note
    Each finding is a `json` object within a list.

### JSON-ASFF

???+ note
    Only available when using `--security-hub` or `--output-formats json-asff`

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
}]
```

???+ note
    Each finding is a `json` object within a list.

### HTML

The following image is an example of the HTML output:

<img src="../img/reporting/html-output.png">

## V4 Deprecations

Some deprecations have been made to unify formats and improve outputs.


### JSON

Native JSON format has been deprecated in favor of JSON [OCSF](https://schema.ocsf.io/) `v1.1.0`.

The following is the mapping between the native JSON and the Detection Finding from the JSON-OCSF:

| Native JSON Prowler v3 | JSON-OCSF v.1.1.0 |
| --- |---|
| AssessmentStartTime | event_time |
| FindingUniqueId | finding_info.uid |
| Provider | cloud.provider |
| CheckID | metadata.event_code |
| CheckTitle | finding_info.title |
| CheckType | finding_info.types |
| ServiceName | resources.group.name |
| SubServiceName | _Not mapped yet_ |
| Status | status_code |
| StatusExtended | status_detail |
| Severity | severity |
| ResourceType | resources.type |
| ResourceDetails | resources.data.details |
| Description | finding_info.desc |
| Risk | risk_details |
| RelatedUrl | unmapped.related_url |
| Remediation.Recommendation.Text | remediation.desc |
| Remediation.Recommendation.Url | remediation.references |
| Remediation.Code.NativeIaC | remediation.references |
| Remediation.Code.Terraform | remediation.references |
| Remediation.Code.CLI | remediation.references |
| Remediation.Code.Other | remediation.references |
| Compliance | unmapped.compliance |
| Categories | unmapped.categories |
| DependsOn | unmapped.depends_on |
| RelatedTo | unmapped.related_to |
| Notes | unmapped.notes |
| Profile | _Not mapped yet_ |
| AccountId | cloud.account.uid |
| OrganizationsInfo.account_name | cloud.account.name |
| OrganizationsInfo.account_email | _Not mapped yet_ |
| OrganizationsInfo.account_arn | _Not mapped yet_ |
| OrganizationsInfo.account_org | cloud.org.name |
| OrganizationsInfo.account_tags | cloud.account.labels |
| Region | resources.region |
| ResourceId | resources.name |
| ResourceArn | resources.uid |
| ResourceTags | resources.labels |


### CSV Columns

In Prowler v3 each provider had some specific columns, different from the rest. These are the cases that have changed in Prowler v4:

| Provider | v3 | v4 |
| --- |---|---|
| AWS | PROFILE | AUTH_METHOD |
| AWS | ACCOUNT_ID| ACCOUNT_UID |
| AWS | ACCOUNT_ORGANIZATION_ARN | ACCOUNT_ORGANIZATION_UID |
| AWS | ACCOUNT_ORG | ACCOUNT_ORGANIZATION_NAME |
| AWS | FINDING_UNIQUE_ID | FINDING_UID |
| AWS | ASSESSMENT_START_TIME | TIMESTAMP |
| AZURE | TENANT_DOMAIN | ACCOUNT_ORGANIZATION_NAME |
| AZURE | SUBSCRIPTION | ACCOUNT_UID |
| GCP | PROJECT_ID | ACCOUNT_UID |
| GCP | LOCATION | REGION |
| AWS / AZURE / GCP | RESOURCE_ID | RESOURCE_NAME |
| AWS / AZURE / GCP | RESOURCE_ARN | RESOURCE_UID |
