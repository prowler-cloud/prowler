# Creating a New Check for a Prowler Provider

This guide explains how to create new checks in Prowler.

**Before proceeding, ensure that a Prowler provider service is already set up. If the required service is unavailable or the attribute to be audited is not retrieved by the service, refer to the [Service](./services.md) documentation.**

## Introduction

Checks are the core component of Prowler. A check is a simple piece of code designed to validate whether a configuration aligns with cybersecurity best practices. Once executed, the check generates a finding, providing the result along with metadata that offers contextual information regarding the outcome, associated risks, and recommended remediation steps.

### Creating a Check for a Provider 

To create a new check for a supported Prowler provider:  
  
- Navigate to the specific service directory associated with the provider.  
  
- Create a folder named after the check within this directory.  
  
- Implement the necessary logic to evaluate the targeted security configuration.

For this example, we will use the `ec2_ami_public` check from the `AWS` provider. 

### Naming Format for Folders

The corresponding folder must be named following the format:`prowler/providers/<provider>/services/<service>/<check_name>`. Consequently, the folder will be named as follows: `prowler/providers/aws/services/ec2/ec2_ami_public`.  

### Naming Format for Checks  

Checks must be named following the format: `service_subservice_resource_action`.

???+ note A subservice represents an individual component of a service that undergoes auditing. In some cases, it may correspond to a shortened version of the class attribute accessed within the check.

File Creation

Each check in Prowler follows a straightforward structure. Within the newly created folder, three files must be added to implement the check logic:

- `__init__.py` (empty file) – Ensures Python treats the check folder as a package.
- `check_name.py` (check implementation file) – Contains the check logic, following the prescribed format. Please refer to the [check](./checks.md#check) for more information.
- `check_name.metadata.json` (metadata file) – Defines the check’s metadata for contextual information. Please refer to the [check metadata](./checks.md#check-metadata) for more information.

## Prowler’s Check Structure

Prowler’s check structure is really uncomplicated. It follows a dynamic loading approach based on predefined paths, ensuring seamless integration of new checks into a provider's service without additional manual steps.

Below the code for the `ec2_ami_public` check is presented:

```python title="Check Class"

# Required Imports

# At the beginning of the check implementation file, import the following modules:

# - Check class: Handles metadata retrieval
#   - Exposes the `metadata()` method, which
#       returns a JSON representation of the check’s metadata.
#       Refer to the Check Metadata Model section below for details.
#   - Each must be enforced to require the `execute()` function

from prowler.lib.check.models import Check, Check_Report_AWS

# Importing the Provider Service Client

# To integrate the provider service client, import the necessary module:

from prowler.providers.aws.services.ec2.ec2_client import ec2_client

# For more details on service client usage, refer to the [Service Documentation].

# Defining the Check Class

# Each check must be implemented as a Python class with the same name as its corresponding file.

# The class must inherit from the Check base class to ensure proper execution within Prowler.

class ec2_ami_public(Check):

    """ec2_ami_public verifies if an EC2 AMI is publicly shared"""

    # Implementing the execute() Method

Within the check class, define the execute(self) method.
    
    # This method is required by the Check base class.
    # It ensures compliance with Prowler’s check structure, enabling 
    # dynamic execution.

    def execute(self):

    # Implementing the execute() Method

    # Within the execute(self) method,

        # initialize a list to store findings:

        findings = []

        # Next, iterate over the target resources using the provider service client.

        # In this case, the check will process EC2 AMIs retrieved from the # ec2_client.images object: "ec2_client.images" object.
        
        for image in ec2_client.images:

            # For each resource, initialize an instance of the Check_Report_AWS class,
            # passing the check’s metadata retrieved using the metadata() function:
            
            report = Check_Report_AWS(self.metadata())
            
            # Please see Required Imports above for details.

            # Required Fields for Prowler Checks
            # Each Prowler check must include the following required fields to ensure proper execution and reporting:
            
            # Check_Report_AWS fields:
            # - region
            # - resource_id
            # - resource_arn
            # - resource_tags
            # - status
            # - status_extended
            
            report.region = image.region
            report.resource_id = image.id
            report.resource_arn = image.arn
            
            # Setting Resource Tags and Check Logic
            
            # When implementing a check, ensure that resource tags (resource_tags) are populated if the resource supports tagging.
            # Verify this capability within the respective service documentation:
            
            report.resource_tags = image.tags

            # Next, define the check business logic.
            # The logic should remain simple, as Prowler handles the core processing.
            # The check is responsible only for
            # parsing and interpreting the provided data:
            
            report.status = "PASS"
            report.status_extended = f"EC2 AMI {image.id} is not public."

            # Evaluating Public Visibility and Reporting Findings
            # Each image object includes a boolean attribute, public, indicating whether the AMI is publicly shared.
            # To assess its status, implement the following logic:
            
            if image.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 AMI {image.id} is currently public."
                )

            # Once the check is performed,
            # append the report object to the findings list at the same level:
            
            findings.append(report)

        # Finally, return the findings list to Prowler for processing:
        
        return findings
```

### Check Statuses

Required Fields: status and status\_extended  

Each check **must** populate the `report.status` and `report.status_extended` fields according to the following criteria:

- Status field: `report.status`
  
  - `PASS` – Assigned when the check confirms compliance with the configured value.
  - `FAIL` – Assigned when the check detects non-compliance with the configured value.
  - `MANUAL` – This status must not be used unless manual verification is necessary to determine whether the status (`report.status`) passes (`PASS`) or fails (`FAIL`).

- Status extended field: `report.status_extended`
  
  - It **must** end with a period (`.`).
  - It **must** include the audited service, the resource, and a concise explanation of the check result, for instance: `EC2 AMI ami-0123456789 is not public.`.

### Check Regions

Required Field: report.region  
E
ach check **must** populate the `report.region` field according to the following criteria:

- Regional Resources: Use the `region` attribute from the resource object. Note that the attribute name varies by provider: Azure \& GCP: `location`  
  
Kubernetes (K8s): `namespace`.

- Global Resources: Use the `service_client.region` attribute from the service client object.

### Check Severity Levels

The severity of each check is defined in the metadata file using the `Severity` field. Severity values are always lowercase and must be one of the predefined categories below.

- `critical`
- `high`
- `medium`
- `low`
- `informational`

If the check involves multiple scenarios that may alter its severity, adjustments can be made dynamically within the check’s logic using the severity `report.check_metadata.Severity` attribute:

```python
if <valid for more than 6 months>:
    report.status = "PASS"
    report.check_metadata.Severity = "informational"
    report.status_extended = f"RDS Instance {db_instance.id} certificate has over 6 months of validity left."
elif <valid for more than 3 months>:
    report.status = "PASS"
    report.check_metadata.Severity = "low"
    report.status_extended = f"RDS Instance {db_instance.id} certificate has between 3 and 6 months of validity."
elif <valid for more than 1 month>:
    report.status = "FAIL"
    report.check_metadata.Severity = "medium"
    report.status_extended = f"RDS Instance {db_instance.id} certificate less than 3 months of validity."
elif <valid for less than 1 month>:
    report.status = "FAIL"
    report.check_metadata.Severity = "high"
    report.status_extended = f"RDS Instance {db_instance.id} certificate less than 1 month of validity."
else:
    report.status = "FAIL"
    report.check_metadata.Severity = "critical"
    report.status_extended = (
        f"RDS Instance {db_instance.id} certificate has expired."
    )
```

### Resource ID, Name and ARN

Required Fields: status and status\_extended  

Each check **must** populate the `report.resource_id` and `report.resource_arn` fields according to the following criteria:

- AWS
  
  - Resouce ID and ARN:
    - When auditing an AWS account, the following identifiers must be included:
      - `resource_id` — AWS Account Number
      - `resource_arn` — AWS Account Root ARN
    - If the ARN cannot be retrieved directly from the audited resource, construct a valid ARN using the `resource_id` component as the audited entity. Examples:
      - Bedrock — `arn:<partition>:bedrock:<region>:<account-id>:model-invocation-logging`
      - DirectConnect — `arn:<partition>:directconnect:<region>:<account-id>:dxcon`
    - If no actual resource to audit exists, proceed as follows:
      - resource\_id — `resource_type/unknown`
      - resource\_arn — `arn:<partition>:<service>:<region>:<account-id>:<resource_type>/unknown`
      - Examples:
        - AWS Security Hub — `arn:<partition>:security-hub:<region>:<account-id>:hub/unknown`
        - Access Analyzer — `arn:<partition>:access-analyzer:<region>:<account-id>:analyzer/unknown`
        - GuardDuty — `arn:<partition>:guardduty:<region>:<account-id>:detector/unknown`

- GCP
  
  - Resource ID — `report.resource_id`
    - GCP Resource — Resource ID
  - Resource Name — `report.resource_name`
    - GCP Resource — Resource Name

- Azure
  
  - Resource ID — `report.resource_id`
    - Azure Resource — Resource ID
  - Resource Name — `report.resource_name`
    - Azure Resource — Resource Name

### Python Model

The following is the Python model corresponding to the class of the check.

As of April 11th 2024 the `Check_Metadata_Model` can be found [here](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py#L36-L82).

```python
class Check(ABC, Check_Metadata_Model):
    """Prowler Check"""

    def __init__(self, **data):
        """The __init__ function of the check. Calls the CheckMetadataModel init."""
        # Parse the metadata file of the check
        metadata_file = (
            os.path.abspath(sys.modules[self.__module__].__file__)[:-3]
            + ".metadata.json"
        )
        # Store it for validation with Pydantic
        data = Check_Metadata_Model.parse_file(metadata_file).dict()
        # Calls parents __init__ function
        super().__init__(**data)

    def metadata(self) -> dict:
        """Return the JSON representation of the metadata of the check"""
        return self.json()

    @abstractmethod
    def execute(self):
        """Execute the logic of the check"""
```

### Using the Audit Configuration

Prowler has a [configuration file](../tutorials/configuration_file.md) which is used to pass certain configuration values to the checks. For example:

```python title="ec2_securitygroup_with_many_ingress_egress_rules.py"
class ec2_securitygroup_with_many_ingress_egress_rules(Check):
    def execute(self):
        findings = []

        # max_security_group_rules, default: 50
        max_security_group_rules = ec2_client.audit_config.get(
            "max_security_group_rules", 50
        )
        for security_group_arn, security_group in ec2_client.security_groups.items():
```

```yaml title="config.yaml"
# AWS Configuration

  aws:
  
  # AWS EC2 Configuration

  # aws.ec2_securitygroup_with_many_ingress_egress_rules
  # The default value is 50 rules
  
  max_security_group_rules: 50
```

Using Configuration Values in the Service Client  

As in the above code, within the service client (e.g., `ec2_client`),the object `audit_config` is a Python dictionary that stores values read from the configuration file.

Checking and Using Configuration Values  

Verify whether the required value is present in the configuration file before using it. If the value is missing, add it to the `config.yaml` and retrieve it within the check implementation.

???+ note Always use the `dictionary.get(value, default)` syntax to ensure a default value is set when the configuration value is not present.

## Check Metadata

Each Prowler check has associated metadata, which is stored in a file named `check_name.metadata.json` located at the same level as the check’s folder. This file contains essential metadata for the check's execution and contextual information.

???+ note Although comments are included in the following example for clarity, they cannot be present in the actual JSON file, as the JSON format does not support comments.

```json
{
  # Provider holds the Prowler provider to which the checks belong.
  "Provider": "aws",
  # CheckID holds check name
  "CheckID": "ec2_ami_public",
  # CheckTitle holds the title of the check.
  "CheckTitle": "Ensure there are no EC2 AMIs set as Public.",
  # CheckType holds Software and Configuration Checks. Check the following address for details:
  # https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html#Types
  "CheckType": [
    "Infrastructure Security"
  ],
  # ServiceName holds the provider service name.
  "ServiceName": "ec2",
  # SubServiceName holds the service's subservice or resource used by the check.
  "SubServiceName": "ami",
  # ResourceIdTemplate holds the unique ID for the resource used by the check.
  "ResourceIdTemplate": "arn:partition:service:region:account-id:resource-id",
  # Severity holds the check's severity, always in lowercase (critical, high, medium, low or informational).
  "Severity": "critical",
  # ResourceType is only intended for AWS. It retains the type stated here:
  # https://docs.aws.amazon.com/securityhub/latest/userguide/asff-resources.html
  # Formatting If a resource type does not exist, use its CloudFormation type as a reference. Remove all occurrences of "::" and apply PascalCase, ensuring only the first letter of each word is capitalized. Example Conversion: "AWS::EC2::Instance" → "AwsEc2Instance"
  # For details on the types of CloudFormation, check: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html.
  # If the resource type does not exist in the CloudFormation types, use "Other".
  "ResourceType": "Other",
  # Description holds the title of the check. In this case, it remains as the title in CheckTitle.
  "Description": "Ensure there are no EC2 AMIs set as Public.",
  # Risk holds the check risk if the result is FAIL.
  "Risk": "Publicly Accessible AMIs: When an Amazon Machine Image (AMI) is publicly accessible, it becomes available under Community AMIs, allowing any AWS account holder to use it for launching EC2 instances. Since AMIs may contain snapshots of applications—including sensitive data—exposing them publicly presents a security risk. It is strongly recommended to restrict AMI visibility to prevent unauthorized access.",
  # Additional Resources
  The RelatedUrl field provides a reference URL for more details on the check’s purpose:
  "RelatedUrl": "",
  # Remediation holds the information to help the practitioner fix the issue if the check raises a FAIL.
  "Remediation": {
    # Code holds different methods to remediate the FAIL finding.
    "Code": {
      # CLI holds the command in the provider native CLI to remediate it.
      "CLI": "aws ec2 modify-image-attribute --region <REGION> --image-id <EC2_AMI_ID> --launch-permission {\"Remove\":[{\"Group\":\"all\"}]}",
      # NativeIaC holds the native IaC code to remediate it. Use: "https://docs.bridgecrew.io/docs"
      "NativeIaC": "",
      # Other holds the other commands, scripts or code to remediate it. Use: "https://www.trendmicro.com/cloudoneconformity"
      "Other": "https://docs.prowler.com/checks/public_8#aws-console",
      # Terraform holds the Terraform code to remediate it. Use: "https://docs.bridgecrew.io/docs"
      "Terraform": ""
    },
    # Recommendation holds the recommendation for this check with a description and the corresponding URL
    "Recommendation": {
      "Text": "Recommendation: Restrict AMI Public Access
It is recommended to prevent EC2 AMIs from being publicly accessible or listed as Community AMIs, as this can expose sensitive application snapshots to unauthorized users.

Additional Information
For guidance on managing AMI sharing permissions, refer to the official AWS documentation:",
      "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/cancel-sharing-an-AMI.html"
    }
  },
  # Categories holds the category or categories where the check can be included, in case it is applied.
  "Categories": [
    "internet-exposed"
  ],
  # The DependsOn attribute is currently inactive,
  # but will eventually store references to other checks that this check depends on.
  "DependsOn": [],
  # The RelatedTo attribute is currently inactive,
  # but will eventually store references to other checks that this check is related to.
  "RelatedTo": [],
  # Notes holds additional information not covered in this file.
  "Notes": ""
}
```

### Remediation Code Guidelines

To populate the Remediation Code, reference the following knowledge sources:

- Official documentation for the provider
- Prowler Checks Index:  
https://docs.prowler.com/checks/checks-index
- TrendMicro Cloud One Conformity:  
https://www.trendmicro.com/cloudoneconformity
- CloudMatos Remediation Repository:  
https://github.com/cloudmatos/matos/tree/master/remediations

### The RelatedURL and Recommendation Fields  

The RelatedURL field must reference an official provider documentation page, such as: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html

If no official documentation is available, use the Risk and Recommendation texts from the TrendMicro [CloudConformity](https://www.trendmicro.com/cloudoneconformity) guide.

### Python Model

The following is the Python model corresponding to the metadata model of the check. Pydantic's [BaseModel](https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel) was used as the parent class.

As of August 5th 2023 the `Check_Metadata_Model` can be found [here](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py#L34-L56).

```python
class Check_Metadata_Model(BaseModel):
    """Check Metadata Model"""

    Provider: str
    CheckID: str
    CheckTitle: str
    CheckType: list[str]
    ServiceName: str
    SubServiceName: str
    ResourceIdTemplate: str
    Severity: str
    ResourceType: str
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    Categories: list[str]
    DependsOn: list[str]
    RelatedTo: list[str]
    Notes: str
    # Compliance was set to None in order to
    # store the compliance if later supplied.
    Compliance: list = None
```