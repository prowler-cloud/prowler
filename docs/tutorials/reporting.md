# Reporting in Prowler

Prowler generates security assessment reports in multiple formats, ensuring compatibility with various analysis tools and AWS integrations.

## Default Report Generation

By default, Prowler outputs reports in CSV and JSON-[OCSF](https://schema.ocsf.io/) formats:

```console
prowler <provider> -M csv json-ocsf json-asff html
```

If you require reports in JSON-ASFF (used by AWS Security Hub), set it using the `-M/--output-modes/--output-formats` flag, as in the following example:

```console
prowler <provider> --output-formats json-asff
```

## Compliance Reports

All compliance-related reports are automatically generated when Prowler is executed. These outputs are stored in the `/output/compliance` directory.

## Custom Output Flags

By default, Prowler creates a file inside the `output` directory named: `prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format`.

However, both the output file name and directory can be personalised:

- Custom output report name:

You can use the flag `-F`/`--output-filename`

```console
prowler <provider> -M csv json-ocsf json-asff -F <custom_report_name>
```


- Custom output directory:

You can use the flag `-o`/`--output-directory`

```console
prowler <provider> -M csv json-ocsf json-asff -o <custom_report_directory>
```

???+ note
    Both flags can be used simultaneously to provide a custom directory and filename. `console prowler <provider> -M csv json-ocsf json-asff \ -F <custom_report_name> -o <custom_report_directory>`

## Output timestamp format

By default, the timestamp format of the output files is ISO 8601. This can be changed with the flag `--unix-timestamp` generating the timestamp fields in pure unix timestamp format.

## Supported Output Formats

Prowler natively supports the following reporting output formats:

- CSV
- JSON-OCSF
- JSON-ASFF
- HTML

Hereunder is the structure for each of the supported report formats by Prowler:

### CSV

The CSV format follows a standardized structure across all providers. The following are the available columns:

- AUTH\_METHOD
- TIMESTAMP
- ACCOUNT\_UID
- ACCOUNT\_NAME
- ACCOUNT\_EMAIL
- ACCOUNT\_ORGANIZATION\_UID
- ACCOUNT\_ORGANIZATION\_NAME
- ACCOUNT\_TAGS
- FINDING\_UID
- PROVIDER
- CHECK\_ID
- CHECK\_TITLE
- CHECK\_TYPE
- STATUS
- STATUS\_EXTENDED
- MUTED
- SERVICE\_NAME
- SUBSERVICE\_NAME
- SEVERITY
- RESOURCE\_TYPE
- RESOURCE\_UID
- RESOURCE\_NAME
- RESOURCE\_DETAILS
- RESOURCE\_TAGS
- PARTITION
- REGION
- DESCRIPTION
- RISK
- RELATED\_URL
- REMEDIATION\_RECOMMENDATION\_TEXT
- REMEDIATION\_RECOMMENDATION\_URL
- REMEDIATION\_CODE\_NATIVEIAC
- REMEDIATION\_CODE\_TERRAFORM
- REMEDIATION\_CODE\_CLI
- REMEDIATION\_CODE\_OTHER
- COMPLIANCE
- CATEGORIES
- DEPENDS\_ON
- RELATED\_TO
- NOTES
- PROWLER\_VERSION
- ADDITIONAL\_URLS

#### CSV Headers Mapping

The following table shows the mapping between the CSV headers and the the providers fields:

| Open Source Consolidated| AWS| GCP| AZURE| KUBERNETES
|----------|----------|----------|----------|----------
| auth\_method| profile| principal| identity\_type : identity\_id| in-cluster/kube-config
| provider| provider| provider| provider| provider
| account\_uid| account\_id / account\_arn| project\_id| subscription\_id| cluster
| account\_name| account\_name| project\_name| subscription\_name| context:context
| account\_email| account\_email| N/A| N/A| N/A
| account\_organization\_uid| account\_organizations\_arn| project\_organization\_id| tenant\_id| N/A
| account\_organization\_name| account\_org| project\_organization\_display\_name| tenant\_domain| N/A
| account\_tags| account\_tags| project\_labels| subscription\_tags| N/A
| partition| partition| N/A| region\_config.name| N/A
| region| region| location| location| namespace:namespace
| resource\_name| resource\_id| resource\_name| resource\_name| resource\_name
| resource\_uid| resource\_arn| resource\_id| resource\_id| resource\_id
| finding\_uid| finding\_unique\_id| finding\_unique\_id| finding\_unique\_id| finding\_unique\_id

### JSON-OCSF

The JSON-OCSF output format implements the [Detection Finding](https://schema.ocsf.io/classes/detection_finding) from the [OCSF](https://schema.ocsf.io)

```json
[{
     "message": "Potential secrets found in ECS task definition manufacturer-api with revision 7: Secrets in container manufacturer-api -> Secret Keyword on the environment variable DB_PASSWORD.",
     "metadata": {
         "event_code": "ecs_task_definitions_no_environment_secrets",
         "product": {
             "name": "Prowler",
             "uid": "prowler",
             "vendor_name": "Prowler",
             "version": "5.3.0"
         },
         "profiles": [
             "cloud",
             "datetime"
         ],
         "tenant_uid": "",
         "version": "1.3.0"
     },
     "severity_id": 5,
     "severity": "Critical",
     "status": "New",
     "status_code": "FAIL",
     "status_detail": "Potential secrets found in ECS task definition manufacturer-api with revision 7: Secrets in container manufacturer-api -> Secret Keyword on the environment variable DB_PASSWORD.",
     "status_id": 1,
     "unmapped": {
         "related_url": "",
         "categories": [
             "secrets"
         ],
         "depends_on": [],
         "related_to": [],
         "notes": "",
         "additional_urls": [],
         "compliance": {
             "MITRE-ATTACK": [
                 "T1552"
             ],
             "AWS-Foundational-Security-Best-Practices": [
                 "ecs"
             ],
             "KISA-ISMS-P-2023": [
                 "2.7.1",
                 "2.11.2"
             ],
             "KISA-ISMS-P-2023-korean": [
                 "2.7.1",
                 "2.11.2"
             ],
             "AWS-Well-Architected-Framework-Security-Pillar": [
                 "SEC02-BP03"
             ]
         }
     },
     "activity_name": "Create",
     "activity_id": 1,
     "finding_info": {
         "created_time": 1737995806,
         "created_time_dt": "2025-01-27T17:36:46.855898",
         "desc": "Check if secrets exists in ECS task definitions environment variables.",
         "product_uid": "prowler",
         "title": "Check if secrets exists in ECS task definitions environment variables",
         "types": [
             "Protect",
             "Secure development",
             "Credentials not hard-coded"
         ],
         "uid": "prowler-aws-ecs_task_definitions_no_environment_secrets-123456789012-eu-central-1-manufacturer-api:7"
     },
     "resources": [
         {
             "cloud_partition": "aws",
             "region": "eu-central-1",
             "data": {
                 "details": "",
                 "metadata": {
                     "name": "manufacturer-api",
                     "arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/manufacturer-api:7",
                     "revision": "7",
                     "region": "eu-central-1",
                     "container_definitions": [
                         {
                             "name": "manufacturer-api",
                             "privileged": false,
                             "readonly_rootfilesystem": false,
                             "user": "",
                             "environment": [
                                 {
                                     "name": "DB_HOST",
                                     "value": "some.cluster.eu-central-1.rds.amazonaws.com"
                                 },
                                 {
                                     "name": "DB_PASSWORD",
                                     "value": "somePassword"
                                 }
                             ],
                             "log_driver": "",
                             "log_option": ""
                         }
                     ],
                     "pid_mode": "",
                     "tags": [],
                     "network_mode": "awsvpc"
                 }
             },
             "group": {
                 "name": "ecs"
             },
             "labels": [],
             "name": "manufacturer-api:7",
             "type": "AwsEcsTaskDefinition",
             "uid": "arn:aws:ecs:eu-central-1:123456789012:task-definition/manufacturer-api:7"
         }
     ],
     "category_name": "Findings",
     "category_uid": 2,
     "class_name": "Detection Finding",
     "class_uid": 2004,
     "cloud": {
         "account": {
             "name": "",
             "type": "AWS Account",
             "type_id": 10,
             "uid": "123456789012",
             "labels": []
         },
         "org": {
             "name": "",
             "uid": ""
         },
         "provider": "aws",
         "region": "eu-central-1"
     },
     "remediation": {
         "desc": "Use Secrets Manager or Parameter Store to securely provide credentials to containers without hardcoding the secrets in code or passing them through environment variables. It is currently not possible to delete task definition revisions which contain plaintext secrets. AWS is looking into implementing this feature in 2023, and it is therefore recommended that all plaintext secrets are rotated at the same time as moving the secrets to Secrets Manager or Parameter Store.",
         "references": [
             "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html"
         ]
     },
     "risk_details": "The use of a hard-coded password increases the possibility of password guessing. If hard-coded passwords are used, it is possible that malicious users gain access through the account in question.",
     "time": 1737995806,
     "time_dt": "2025-01-27T17:36:46.855898",
     "type_uid": 200401,
     "type_name": "Detection Finding: Create"
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

| Native JSON Prowler v3| JSON-OCSF v.1.1.0
|----------|----------
| AssessmentStartTime| time\_dt
| FindingUniqueId| finding\_info.uid
| Provider| cloud.provider
| CheckID| metadata.event\_code
| CheckTitle| finding\_info.title
| CheckType| finding\_info.types
| ServiceName| resources.group.name
| SubServiceName| _Not mapped yet_
| Status| status\_code
| StatusExtended| status\_detail
| Severity| severity
| ResourceType| resources.type
| ResourceDetails| resources.data.details
| Description| finding\_info.desc
| Risk| risk\_details
| RelatedUrl| unmapped.related\_url
| Remediation.Recommendation.Text| remediation.desc
| Remediation.Recommendation.Url| remediation.references
| Remediation.Code.NativeIaC| remediation.references
| Remediation.Code.Terraform| remediation.references
| Remediation.Code.CLI| remediation.references
| Remediation.Code.Other| remediation.references
| Compliance| unmapped.compliance
| Categories| unmapped.categories
| DependsOn| unmapped.depends\_on
| RelatedTo| unmapped.related\_to
| AdditionalURLs| unmapped.additional\_urls
| Notes| unmapped.notes
| Profile| _Not mapped yet_
| AccountId| cloud.account.uid
| OrganizationsInfo.account\_name| cloud.account.name
| OrganizationsInfo.account\_email| _Not mapped yet_
| OrganizationsInfo.account\_arn| _Not mapped yet_
| OrganizationsInfo.account\_org| cloud.org.name
| OrganizationsInfo.account\_tags| cloud.account.labels
| Region| resources.region
| ResourceId| resources.name
| ResourceArn| resources.uid
| ResourceTags| resources.labels

### CSV Columns

In Prowler v3 each provider had some specific columns, different from the rest. These are the cases that have changed in Prowler v4:

| Provider| v3| v4
|----------|----------|----------
| AWS| PROFILE| AUTH\_METHOD
| AWS| ACCOUNT\_ID| ACCOUNT\_UID
| AWS| ACCOUNT\_ORGANIZATION\_ARN| ACCOUNT\_ORGANIZATION\_UID
| AWS| ACCOUNT\_ORG| ACCOUNT\_ORGANIZATION\_NAME
| AWS| FINDING\_UNIQUE\_ID| FINDING\_UID
| AWS| ASSESSMENT\_START\_TIME| TIMESTAMP
| AZURE| TENANT\_DOMAIN| ACCOUNT\_ORGANIZATION\_NAME
| AZURE| SUBSCRIPTION| ACCOUNT\_UID
| GCP| PROJECT\_ID| ACCOUNT\_UID
| GCP| LOCATION| REGION
| AWS / AZURE / GCP| RESOURCE\_ID| RESOURCE\_NAME
| AWS / AZURE / GCP| RESOURCE\_ARN| RESOURCE\_UID
