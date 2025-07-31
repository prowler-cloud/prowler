# Prowler Checks

This guide explains how to create new checks in Prowler.

## Introduction

Checks are the core component of Prowler. A check is a piece of code designed to validate whether a configuration aligns with cybersecurity best practices. Execution of a check yields a finding, which includes the result and contextual metadata (e.g., outcome, risks, remediation).

### Creating a Check

The most common high level steps to create a new check are:

1. Prerequisites:
    - Verify the check does not already exist by searching [Prowler Hub](https://hub.prowler.com) or checking `prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>/`.
    - Ensure required provider and service exist. If not, follow the [Provider](./provider.md) and [Service](./services.md) documentation to create them.
    - Confirm the service has implemented all required methods and attributes for the check (in most cases, you will need to add or modify some methods in the service to get the data you need for the check).
2. Navigate to the service directory. The path should be as follows: `prowler/providers/<provider>/services/<service>`.
3. Create a check-specific folder. The path should follow this pattern: `prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>`. Adhere to the [Naming Format for Checks](#naming-format-for-checks).
4. Populate the folder with files as specified in [File Creation](#file-creation).
5. Run the check locally to ensure it works as expected. For checking you can use the CLI in the next way:
    - To ensure the check has been detected by Prowler: `poetry run python prowler-cli.py <provider> --list-checks | grep <check_name>`.
    - To run the check, to find possible issues: `poetry run python prowler-cli.py <provider> --log-level ERROR --verbose --check <check_name>`.
6. If the check is working as expected, you can submit a PR to Prowler.

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
    """
    Ensure that <resource> meets <security_requirement>.

    This check evaluates whether <specific_condition> to ensure <security_benefit>.
    - PASS: <description_of_compliant_state(s)>.
    - FAIL: <description_of_non_compliant_state(s)>.
    """

    def execute(self):
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
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
  "CheckID": "service_resource_security_setting",
  "CheckTitle": "Service resource has security setting enabled",
  "CheckType": [],
  "ServiceName": "service",
  "SubServiceName": "",
  "ResourceIdTemplate": "",
  "Severity": "medium",
  "ResourceType": "Other",
  "Description": "This check verifies that the service resource has the required **security setting** enabled to protect against potential vulnerabilities.\n\nIt ensures that the resource follows security best practices and maintains proper access controls. The check evaluates whether the security configuration is properly implemented and active.",
  "Risk": "Without proper security settings, the resource may be vulnerable to:\n\n- **Unauthorized access** - Malicious actors could gain entry\n- **Data breaches** - Sensitive information could be compromised\n- **Security threats** - Various attack vectors could be exploited\n\nThis could result in compliance violations and potential financial or reputational damage.",
  "RelatedUrl": [
    "https://example.com/security-documentation",
    "https://example.com/best-practices"
  ],
  "Remediation": {
    "Code": {
      "CLI": "provider-cli service enable-security-setting --resource-id resource-123",
      "NativeIaC": "```yaml\nType: Provider::Service::Resource\nProperties:\n  SecuritySetting: enabled\n  ResourceId: resource-123\n```",
      "Other": "1. Open the provider management console\n2. Navigate to the service section\n3. Select the resource\n4. Enable the security setting\n5. Save the configuration",
      "Terraform": "```hcl\nresource \"provider_service_resource\" \"example\" {\n  resource_id      = \"resource-123\"\n  security_setting = true\n}\n```"
    },
    "Recommendation": {
      "Text": "Enable security settings on all service resources to ensure proper protection. Regularly review and update security configurations to align with current best practices.",
      "Url": ""
    }
  },
  "Categories": ["internet-exposed", "secrets"],
  "DependsOn": [],
  "RelatedTo": ["service_resource_security_setting", "service_resource_security_setting_2"],
  "Notes": "This is a generic example check that should be customized for specific provider and service requirements."
}
```

### Metadata Fields and Their Purpose

#### Provider

The Prowler provider related to the check. The name **must** be lowercase and match the provider folder name. For supported providers refer to [Prowler Hub](https://hub.prowler.com/check) or directly to [Prowler Code](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

#### CheckID

The unique identifier for the check inside the provider. This field **must** match the check's folder, Python file, and JSON metadata file name. For more information about naming, refer to the [Naming Format for Checks](#naming-format-for-checks) section.

#### CheckTitle

The `CheckTitle` field defines clearly and succinctly what best practice is being evaluated and which resource(s) each finding applies to. The title should be specific, concise (no more than 150 characters), and reference the relevant resource(s) involved.

For most checks, which produce one finding per resource, the `CheckTitle` should mention the individual resource. For example, if the check assesses whether multi-factor authentication (MFA) is enabled for each user, the title might be: *"User has multi-factor authentication enabled."*

If a finding covers multiple resources at once, the `CheckTitle` should indicate this scope, such as: *"All users do not have multi-factor authentication enabled."*

Always write the `CheckTitle` to state the best practice being assessed and to clearly identify the affected resource(s). Avoid generic or action-oriented phrases like "Check" or "Ensure." Instead, use a descriptive format that states the resource and the best practice.

**Good Examples:**

- `"EC2 AMI is not public"` - Clear, specific, states the resource and best practice.
- `"Security group does not allow ingress from 0.0.0.0/0 to SSH port 22"` - Specific about the resource and security requirement.
- `"IAM user has multi-factor authentication enabled"` - States the resource and security best practice.
- `"EBS volume is encrypted"` - Concise, clear about the resource and requirement.
- `"Kubernetes pod does not run as root user"` - Specific about the resource and security best practice.

**Examples to Avoid:**

- `"Check if EC2 instances are encrypted"` - Uses "Check" action verb, totally unnecessary because we already know the check is checking.
- `"Ensure security groups are properly configured"` - Too generic, doesn't specify what "properly" means.
- `"Verify encryption settings"` - Too vague, doesn't identify specific resources.
- `"Monitor access controls"` - Generic, doesn't specify what to monitor.

#### CheckType

???+ warning
    This field is only applicable to the AWS provider.

It follows the [AWS Security Hub Types](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html#Types) format using the pattern `namespace/category/classifier`.

#### ServiceName

The name of the provider service being audited. Must be lowercase and match the service folder name. For supported services refer to [Prowler Hub](https://hub.prowler.com/check) or the [Prowler Code](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

#### SubServiceName

This field is in the process of being deprecated and should be **left empty**.

#### ResourceIdTemplate

This field is in the process of being deprecated and should be **left empty**.

#### Severity

Severity level if the check fails. Must be one of: `critical`, `high`, `medium`, `low`, or `informational`, and written in lowercase. See [Prowler's Check Severity Levels](#prowlers-check-severity-levels) for details.

#### ResourceType

The type of resource being audited. This field helps categorize and organize findings by resource type for better analysis and reporting. For each provider:

- **AWS**: Use [Security Hub resource types](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-resources.html) or PascalCase CloudFormation types removing the `::` separator used in CloudFormation templates (e.g., in CloudFormation template the type of an EC2 instance is `AWS::EC2::Instance` but in the check it should be `AwsEc2Instance`). Use `Other` if none apply.
- **Azure**: Use types from [Azure Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources), for example: `Microsoft.Storage/storageAccounts`.
- **Google Cloud**: Use [Cloud Asset Inventory asset types](https://cloud.google.com/asset-inventory/docs/asset-types), for example: `compute.googleapis.com/Instance`.
- **Kubernetes**: Use types shown under `KIND` from `kubectl api-resources`.
- **M365 / GitHub**: Leave empty due to lack of standardized types in API responses.

#### Description

A concise, natural language explanation that **clearly describes what the finding means**, focusing on clarity and context rather than technical implementation details. Use simple paragraphs with line breaks if needed, but avoid sections, code blocks, or complex formatting. This field is limited to maximum 400 characters.

#### Risk

A clear, natural language explanation of **why this finding poses a cybersecurity risk**. Focus on how it may impact confidentiality, integrity, or availability. If those do not apply, describe any relevant operational or financial risks. Use simple paragraphs with line breaks if needed, but avoid sections, code blocks, or complex formatting. Limit your explanation to 400 characters.

#### RelatedUrl

A list of one or more official documentation URLs for further reading. These should be authoritative sources that provide additional context, best practices, or detailed information about the security control being checked. Prefer official provider documentation, security standards, or well-established security resources. Avoid third-party blogs or unofficial sources unless they are highly reputable and directly relevant.

#### Remediation

- **Code**
    - **CLI**: Use Markdown format to provide multiple commands or code blocks where applicable.
    - **NativeIaC / Terraform**: Provide actual code blocks when possible. Use line breaks for readability.
    - **Other**: Natural language, step-by-step remediation in Markdown format using native web interfaces (e.g., AWS Console, Azure Portal) or other tool that is not any of the other options.
- **Recommendation**
    - **Text**: Explanation in natural language using Markdown format, explaining the best practice in general terms that is usually used to avoid the check to fail.
      For example:
        - *"Avoid exposing sensitive resources directly to the Internet; configure access controls to limit exposure."*
        - *"Apply the principle of least privilege when assigning permissions to users and services."*
        - *"Regularly review and update your security configurations to align with current best practices."*
    - **Url**: *Deprecated*. Use `RelatedUrl` instead.

#### Categories

One or more functional groupings used for execution filtering (e.g., `internet-exposed`). You can define new categories just by adding to this field. Here are all the categories already defined in Prowler:

| Category                | Definition                                                                                                                                                                                                                                 |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| encryption              | Ensure data is encrypted in transit and/or at rest, including key management practices.                                                                                                   |
| internet-exposed        | Checks that limit or flag public access to services, APIs, or assets from the Internet.                                                                                                              |
| logging                 | Ensures appropriate logging of events, activities, and system interactions for traceability.                                                                                                       |
| secrets                 | Manages and protects credentials, API keys, tokens, and other sensitive information.                                                                                                               |
| resilience              | Ensures systems can maintain availability and recover from disruptions, failures, or degradation. Includes redundancy, fault-tolerance, auto-scaling, backup, disaster recovery, and failover strategies. |
| threat-detection        | Identifies suspicious activity or behaviors using IDS, malware scanning, or anomaly detection.                                                                                                      |
| trust-boundaries        | Enforces isolation or segmentation between different trust levels (e.g., VPCs, tenants, network zones).                                                                                            |
| vulnerabilities         | Detects or remediates known software, infrastructure, or config vulnerabilities (e.g., CVEs).                                                                                                      |
| cluster-security        | Secures Kubernetes cluster components such as API server, etcd, and role-based access.                                                                                                             |
| container-security      | Ensures container images and runtimes follow security best practices.                                                                                        |
| node-security           | Secures nodes running containers or services.                                                                                                        |
| gen-ai                  | Checks related to safe and secure use of generative AI services or models.                                                                                                                        |
| ci-cd                   | Ensures secure configurations in CI/CD pipelines.                                                                                                         |
| identity-access         | Governs user and service identities, including least privilege, MFA, and permission boundaries.                                                                                                    |
| email-security          | Ensures detection and protection against phishing, spam, spoofing, etc.                                                                                                                            |
| forensics-ready         | Ensures systems are instrumented to support post-incident investigations. Any digital trace or evidence (logs, volume snapshots, memory dumps, network captures, etc.) preserved immutably and accompanied by integrity guarantees, which can be used in a forensic analysis. |
| software-supply-chain   | Detects or prevents tampering, unauthorized packages, or third-party risks in software supply chain.                                                                                               |
| e3                      | M365-specific controls enabled by or dependent on an E3 license (e.g., baseline security policies, conditional access).                                                                            |
| e5                      | M365-specific controls enabled by or dependent on an E5 license (e.g., advanced threat protection, audit, DLP, and eDiscovery).                                                                    |

#### DependsOn

Specifies checks that if they are PASS, this check will be a PASS too or it is not going to give any finding.

#### RelatedTo

Specifies checks that are conceptually related, even if they do not share a technical dependency.

#### Notes

Any additional information not covered in the above fields.


### Python Model Reference

The metadata structure is enforced in code using a Pydantic model. For reference, see the [`CheckMetadata`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py).

## Generic Check Patterns and Best Practices

### Common Patterns

- Every check is implemented as a class inheriting from `Check` (from `prowler.lib.check.models`).
- The main logic is implemented in the `execute()` method (**only method that must be implemented**), which always returns a list of provider-specific report objects (e.g., `CheckReport<Provider>`)—one per finding/resource. If there are no findings/resources, return an empty list.
- **Never** use the provider's client directly; instead, use the service client (e.g., `<service>_client`) and iterate over its resources.
- For each resource, create a provider-specific report object, populate it with metadata, resource details, status (`PASS`, `FAIL`, etc.), and a human-readable `status_extended` message.
- Use the `metadata()` method to attach check metadata to each report.
- Checks are designed to be idempotent and stateless: they do not modify resources, only report on their state.

### Best Practices

- Use clear, actionable, and user-friendly language in `status_extended` to explain the result. Always provide information to identify the resource.
- Use helper functions/utilities for repeated logic to avoid code duplication. Save them in the `lib` folder of the service.
- Handle exceptions gracefully: catch errors per resource, log them, and continue processing other resources.
- Document the check with a class and function level docstring explaining what it does, what it checks, and any caveats or provider-specific behaviors.
- Use type hints for the `execute()` method (e.g., `-> list[CheckReport<Provider>]`) for clarity and static analysis.
- Ensure checks are efficient; avoid excessive nested loops. If the complexity is high, consider refactoring the check.
- Keep the check logic focused: one check = one control/requirement. Avoid combining unrelated logic in a single check.

## Specific Check Patterns

Details for specific providers can be found in documentation pages named using the pattern `<provider_name>-details`.
