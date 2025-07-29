# Prowler Checks

This guide explains how to create new checks in Prowler.

## Introduction

Checks are the core component of Prowler. A check is a piece of code designed to validate whether a configuration aligns with cybersecurity best practices. Execution of a check yields a finding, which includes the result and contextual metadata (e.g., outcome, risks, remediation).

### Creating a Check

To create a new check:

- Prerequisites: A Prowler provider and service must exist. Verify support and check for pre-existing checks via [Prowler Hub](https://hub.prowler.com). If the provider or service is not present, please refer to the [Provider](./provider.md) and [Service](./services.md) documentation for creation instructions.

- Navigate to the service directory. The path should be as follows: `prowler/providers/<provider>/services/<service>`.

- Create a check-specific folder. The path should follow this pattern: `prowler/providers/<provider>/services/<service>/<check_name>`. Adhere to the [Naming Format for Checks](#naming-format-for-checks).

- Populate the folder with files as specified in [File Creation](#file-creation).

### Naming Format for Checks

Checks must be named following the format: `service_subservice_resource_action`.

The name components are:

- `service` – The main service being audited (e.g., ec2, entra, iam, etc.)
- `subservice` – An individual component or subset of functionality within the service that is being audited. This may correspond to a shortened version of the class attribute accessed within the check. If there is no subservice, just omit.
- `resource` – The specific resource type being evaluated (e.g., instance, policy, role, etc.)
- `action` – The security aspect or configuration being checked (e.g., public, encrypted, enabled, etc.)

### File Creation

Each check in Prowler follows a straightforward structure. Within the newly created folder, three files must be added to implement the check logic:

- `__init__.py` (empty file) – Ensures Python treats the check folder as a package.
- `<check_name>.py` (code file) – Contains the check logic, following the prescribed format. Please refer to the [prowler's check code structure](./checks.md#prowlers-check-code-structure) for more information.
- `<check_name>.metadata.json` (metadata file) – Defines the check's metadata for contextual information. Please refer to the [check metadata](./checks.md#) for more information.

## Prowler's Check Code Structure

Prowler's check structure is designed for clarity and maintainability. It follows a dynamic loading approach based on predefined paths, ensuring seamless integration of new checks into a provider's service without additional manual steps.

Below the code for a generic check is presented. It is strongly recommended to consult other checks from the same provider and service to understand provider-specific details and patterns. This will help ensure consistency and proper implementation of provider-specific requirements.

Report fields are the most dependent on the provider, consult the `CheckReport<Provider>` class for more information on what can be included in the report [here](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py).

???+ note
    Legacy providers (AWS, Azure, GCP, Kubernetes) follow the `Check_Report_<Provider>` naming convention. This is not recommended for current instances. Newer providers adopt the `CheckReport<Provider>` naming convention. Learn more at [Prowler Code](https://github.com/prowler-cloud/prowler/tree/master/prowler/lib/check/models.py).

```python title="Generic Check Class"
# Required Imports
# Import the base Check class and the provider-specific CheckReport class
from prowler.lib.check.models import Check, CheckReport<Provider>
# Import the provider service client
from prowler.providers.<provider>.services.<service>.<service>_client import <service>_client

# Defining the Check Class
# Each check must be implemented as a Python class with the same name as its corresponding file.
# The class must inherit from the Check base class.
class <check_name>(Check):
    """Short description of what is being checked"""

    def execute(self):
        """Execute <check short description>

        Returns:
            List[CheckReport<Provider>]: A list of reports containing the result of the check.
        """
        findings = []
        # Iterate over the target resources using the provider service client
        for resource in <service>_client.<resources>:
            # Initialize the provider-specific report class, passing metadata and resource
            report = Check_Report_<Provider>(metadata=self.metadata(), resource=resource)
            # Set required fields and implement check logic
            report.status = "PASS"
            report.status_extended = f"<Description about why the resource is compliant>"
            # If some of the information needed for the report is not inside the resource, it can be set it manually here.
            # This depends on the provider and the resource that is being audited.
            # report.region = resource.region
            # report.resource_tags = getattr(resource, "tags", [])
            # ...
            # Example check logic (replace with actual logic):
            if <non_compliant_condition>:
                report.status = "FAIL"
                report.status_extended = f"<Description about why the resource is not compliant>"
            findings.append(report)
        return findings
```

### Data Requirements for Checks in Prowler

One of the most important aspects when creating a new check is ensuring that all required data is available from the service client. Often, default API calls are insufficient. Extending the service class with new methods or resource attributes may be required to fetch and store requisite data.

### Statuses for Checks in Prowler

Required Fields: status and status\_extended

Each check **must** populate the `report.status` and `report.status_extended` fields according to the following criteria:

- Status field: `report.status`
    - `PASS` – Assigned when the check confirms compliance with the configured value.
    - `FAIL` – Assigned when the check detects non-compliance with the configured value.
    - `MANUAL` – This status must not be used unless manual verification is necessary to determine whether the status (`report.status`) passes (`PASS`) or fails (`FAIL`).

- Status extended field: `report.status_extended`
    - It **must** end with a period (`.`).
    - It **must** include the audited service, the resource, and a concise explanation of the check result, for instance: `EC2 AMI ami-0123456789 is not public.`.

### Prowler's Check Severity Levels

The severity of each check is defined in the metadata file using the `Severity` field. Severity values are always lowercase and must be one of the predefined categories below.

- `critical` – Issue that must be addressed immediately.
- `high` – Issue that should be addressed as soon as possible.
- `medium` – Issue that should be addressed within a reasonable timeframe.
- `low` – Issue that can be addressed in the future.
- `informational` – Not an issue but provides valuable information.

If the check involves multiple scenarios that may alter its severity, adjustments can be made dynamically within the check's logic using the severity `report.check_metadata.Severity` attribute:

```python
if <generic_condition_1>:
    report.status = "PASS"
    report.check_metadata.Severity = "informational"
    report.status_extended = f"<Resource> is compliant with <requirement>."
elif <generic_condition_2>:
    report.status = "FAIL"
    report.check_metadata.Severity = "low"
    report.status_extended = f"<Resource> is not compliant with <requirement>: <reason>."
elif <generic_condition_3>:
    report.status = "FAIL"
    report.check_metadata.Severity = "medium"
    report.status_extended = f"<Resource> is not compliant with <requirement>: <reason>."
elif <generic_condition_4>:
    report.status = "FAIL"
    report.check_metadata.Severity = "high"
    report.status_extended = f"<Resource> is not compliant with <requirement>: <reason>."
else:
    report.status = "FAIL"
    report.check_metadata.Severity = "critical"
    report.status_extended = f"<Resource> is not compliant with <requirement>: <critical reason>."
```

### Resource Identification in Prowler

Each check **must** populate the report with an unique identifier for the audited resource. This identifier or identifiers are going to depend on the provider and the resource that is being audited. Here are the criteria for each provider:

- AWS

    - Amazon Resource ID — `report.resource_id`.
        - The resource identifier. This is the name of the resource, the ID of the resource, or a resource path. Some resource identifiers include a parent resource (sub-resource-type/parent-resource/sub-resource) or a qualifier such as a version (resource-type:resource-name:qualifier).
        - If the resource ID cannot be retrieved directly from the audited resource, it can be extracted from the ARN. It is the last part of the ARN after the last slash (`/`) or colon (`:`).
        - If no actual resource to audit exists, this format can be used: `<resource_type>/unknown`

    - Amazon Resource Name — `report.resource_arn`.
        - The [Amazon Resource Name (ARN)](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html) of the audited entity.
        - If the ARN cannot be retrieved directly from the audited resource, construct a valid ARN using the `resource_id` component as the audited entity. Examples:
            - Bedrock — `arn:<partition>:bedrock:<region>:<account-id>:model-invocation-logging`.
            - DirectConnect — `arn:<partition>:directconnect:<region>:<account-id>:dxcon`.
        - If no actual resource to audit exists, this format can be used: `arn:<partition>:<service>:<region>:<account-id>:<resource_type>/unknown`.
            - Examples:
                - AWS Security Hub — `arn:<partition>:security-hub:<region>:<account-id>:hub/unknown`.
                - Access Analyzer — `arn:<partition>:access-analyzer:<region>:<account-id>:analyzer/unknown`.
                - GuardDuty — `arn:<partition>:guardduty:<region>:<account-id>:detector/unknown`.

- GCP

    - Resource ID — `report.resource_id`.
        - Resource ID represents the full, [unambiguous path to a resource](https://google.aip.dev/122#full-resource-names), known as the full resource name. Typically, it follows the format: `//{api_service/resource_path}`.
        - If the resource ID cannot be retrieved directly from the audited resource, by default the resource name is used.
    - Resource Name — `report.resource_name`.
        - Resource Name usually refers to the name of a resource within its service.

- Azure

    - Resource ID — `report.resource_id`.
        - Resource ID represents the full Azure Resource Manager path to a resource, which follows the format: `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}`.
    - Resource Name — `report.resource_name`.
        - Resource Name usually refers to the name of a resource within its service.
        - If the [resource name](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules) cannot be retrieved directly from the audited resource, the last part of the resource ID can be used.

- Kubernetes

    - Resource ID — `report.resource_id`.
        - The UID of the Kubernetes object. This is a system-generated string that uniquely identifies the object within the cluster for its entire lifetime. See [Kubernetes Object Names and IDs - UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids).
    - Resource Name — `report.resource_name`.
        - The name of the Kubernetes object. This is a client-provided string that must be unique for the resource type within a namespace (for namespaced resources) or cluster (for cluster-scoped resources). Names typically follow DNS subdomain or label conventions. See [Kubernetes Object Names and IDs - Names](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names).

- M365

    - Resource ID — `report.resource_id`.
        - If the audited resource has a globally unique identifier such as a `guid`, use it as the `resource_id`.
        - If no `guid` exists, use another unique and relevant identifier for the resource, such as the tenant domain, the internal policy ID, or a representative string following the format `<resource_type>/<name_or_id>`.
    - Resource Name — `report.resource_name`.
        - Use the visible or descriptive name of the audited resource. If no explicit name is available, use a clear description of the resource or configuration being evaluated.
    - Examples:
        - For an organization:
            - `resource_id`: Organization GUID
            - `resource_name`: Organization name
        - For a policy:
            - `resource_id`: Unique policy ID
            - `resource_name`: Policy display name
        - For global configurations:
            - `resource_id`: Tenant domain or representative string (e.g., "userSettings")
            - `resource_name`: Description of the configuration (e.g., "SharePoint Settings")

- GitHub

    - Resource ID — `report.resource_id`.
        - The ID of the Github resource. This is a system-generated integer that uniquely identifies the resource within the Github platform.
    - Resource Name — `report.resource_name`.
        - The name of the Github resource. In the case of a repository, this is just the repository name. For full repository names use the resource `full_name`.

### Configurable Checks in Prowler

See [Configurable Checks](./configurable-checks.md) for detailed information on making checks configurable using the `audit_config` object and configuration file.

## Metadata Structure for Prowler Checks

Each Prowler check must include a metadata file named `<check_name>.metadata.json` that must be located in its directory. This file supplies crucial information for execution, reporting, and context.

### Example Metadata File

Below is a generic example of a check metadata file. **Do not include comments in actual JSON files.**

```json
{
  "Provider": "aws",
  "CheckID": "example_check_id",
  "CheckTitle": "Example Check Title",
  "CheckType": ["Infrastructure Security"],
  "ServiceName": "ec2",
  "SubServiceName": "ami",
  "ResourceIdTemplate": "arn:partition:service:region:account-id:resource-id",
  "Severity": "critical",
  "ResourceType": "Other",
  "Description": "Example description of the check.",
  "Risk": "Example risk if the check fails.",
  "RelatedUrl": "https://example.com",
  "Remediation": {
    "Code": {
      "CLI": "example CLI command",
      "NativeIaC": "",
      "Other": "",
      "Terraform": ""
    },
    "Recommendation": {
      "Text": "Example recommendation text.",
      "Url": "https://example.com/remediation"
    }
  },
  "Categories": ["example-category"],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": ""
}
```

### Metadata Fields and Their Purpose

- **Provider** — The Prowler provider related to the check. The name **must** be lowercase and match the provider folder name. For supported providers refer to [Prowler Hub](https://hub.prowler.com/check) or directly to [Prowler Code](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

- **CheckID** — The unique identifier for the check inside the provider, this field **must** match the check's folder and python file and json metadata file name. For more information about the naming refer to the [Naming Format for Checks](#naming-format-for-checks) section.

- **CheckTitle** — A concise, descriptive title for the check.

- **CheckType** — *For now this field is only standardized for the AWS provider*.
    - For AWS this field must follow the [AWS Security Hub Types](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html#Types) format. So the common pattern to follow is `namespace/category/classifier`, refer to the attached documentation for the valid values for this fields.

- **ServiceName** — The name of the provider service being audited. This field **must** be in lowercase and match with the service folder name. For supported services refer to [Prowler Hub](https://hub.prowler.com/check) or directly to [Prowler Code](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

- **SubServiceName** — The subservice or resource within the service, if applicable. For more information refer to the [Naming Format for Checks](#naming-format-for-checks) section.

- **ResourceIdTemplate** — A template for the unique resource identifier. For more information refer to the [Prowler's Resource Identification](#prowlers-resource-identification) section.

- **Severity** — The severity of the finding if the check fails. Must be one of: `critical`, `high`, `medium`, `low`, or `informational`, this field **must** be in lowercase. To get more information about the severity levels refer to the [Prowler's Check Severity Levels](#prowlers-check-severity-levels) section.

- **ResourceType** — The type of resource being audited. *For now this field is only standardized for the AWS provider*.

    - For AWS use the [Security Hub resource types](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-resources.html) or, if not available, the PascalCase version of the [CloudFormation type](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html) (e.g., `AwsEc2Instance`). Use "Other" if no match exists.

- **Description** — A short description of what the check does.

- **Risk** — The risk or impact if the check fails, explaining why the finding matters.

- **RelatedUrl** — A URL to official documentation or further reading about the check's purpose. If no official documentation is available, use the risk and recommendation text from trusted third-party sources.

- **Remediation** — Guidance for fixing a failed check, including:

    - **Code** — Remediation commands or code snippets for CLI, Terraform, native IaC, or other tools like the Web Console.

    - **Recommendation** — A textual human readable recommendation. Here it is not necessary to include actual steps, but rather a general recommendation about what to do to fix the check.

- **Categories** — One or more categories for grouping checks in execution (e.g., `internet-exposed`). For the current list of categories, refer to the [Prowler Hub](https://hub.prowler.com/check).

- **DependsOn** — Currently not used.

- **RelatedTo** — Currently not used.

- **Notes** — Any additional information not covered by other fields.

### Remediation Code Guidelines

When providing remediation steps, reference the following sources:

- Official provider documentation.
- [Prowler Checks Remediation Index](https://docs.prowler.com/checks/checks-index)
- [TrendMicro Cloud One Conformity](https://www.trendmicro.com/cloudoneconformity)
- [CloudMatos Remediation Repository](https://github.com/cloudmatos/matos/tree/master/remediations)

### Python Model Reference

The metadata structure is enforced in code using a Pydantic model. For reference, see the [`CheckMetadata`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py).
