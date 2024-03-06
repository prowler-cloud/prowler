# Create a new Check for a Provider

Here you can find how to create new checks for Prowler.

**To create a check is required to have a Prowler provider service already created, so if the service is not present or the attribute you want to audit is not retrieved by the service, please refer to the [Service](./services.md) documentation.**

## Introduction
To create a new check for a supported Prowler provider, you will need to create a folder with the check name inside the specific service for the selected provider.

We are going to use the `ec2_ami_public` check form the `AWS` provider as an example. So the folder name will `prowler/providers/aws/services/ec2/ec2_ami_public` (following the format `prowler/providers/<provider>/services/<service>/<check_name>`), with the name of check following the pattern: `service_subservice/resource_action`.

Inside that folder, we need to create three files:

- An empty `__init__.py`: to make Python treat this check folder as a package.
- A `check_name.py` with the above format containing the check's logic. Refer to the [check](./checks.md#check)
- A `check_name.metadata.json` containing the check's metadata. Refer to the [check metadata](./checks.md#check-metadata)

## Check

The Prowler's check structure is very simple and following it there is nothing more to do to include a check in a provider's service because the load is done dynamically based on the paths.

The following is the code for the `ec2_ami_public` check:
```python title="Check Class"
# At the top of the file we need to import the following:
# - Check class which is in charge of the following:
#   - Retrieve the check metadata and expose the `metadata()`
#       to return a JSON representation of the metadata,
#       read more at Check Metadata Model down below.
#   - Enforce that each check requires to have the `execute()` function
from prowler.lib.check.models import Check, Check_Report_AWS

# Then you have to import the provider service client
# read more at the Service documentation.
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

# For each check we need to create a python class called the same as the
# file which inherits from the Check class.
class ec2_ami_public(Check):
    """ec2_ami_public verifies if an EC2 AMI is publicly shared"""

    # Then, within the check's class we need to create the "execute(self)"
    # function, which is enforce by the "Check" class to implement
    # the Check's interface and let Prowler to run this check.
    def execute(self):

        # Inside the execute(self) function we need to create
        # the list of findings initialised to an empty list []
        findings = []

        # Then, using the service client we need to iterate by the resource we
        # want to check, in this case EC2 AMIs stored in the
        # "ec2_client.images" object.
        for image in ec2_client.images:

            # Once iterating for the images, we have to intialise
            # the Check_Report_AWS class passing the check's metadata
            # using the "metadata" function explained above.
            report = Check_Report_AWS(self.metadata())

            # For each Prowler check we MUST fill the following
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
            # The resource_tags should be filled if the resource has the ability
            # of having tags, please check the service first.
            report.resource_tags = image.tags

            # Then we need to create the business logic for the check
            # which always should be simple because the Prowler service
            # must do the heavy lifting and the check should be in charge
            # of parsing the data provided
            report.status = "PASS"
            report.status_extended = f"EC2 AMI {image.id} is not public."

            # In this example each "image" object has a boolean attribute
            # called "public" to set if the AMI is publicly shared
            if image.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 AMI {image.id} is currently public."
                )

            # Then at the same level as the "report"
            # object we need to append it to the findings list.
            findings.append(report)

        # Last thing to do is to return the findings list to Prowler
        return findings
```

### Check Status

All the checks MUST fill the `report.status` and `report.status_extended` with the following criteria:

- Status -- `report.status`
    - `PASS` --> If the check is passing against the configured value.
    - `FAIL` --> If the check is passing against the configured value.
    - `MANUAL` --> This value cannot be used unless a manual operation is required in order to determine if the `report.status` is whether `PASS` or `FAIL`.
- Status Extended -- `report.status_extended`
    - MUST end in a dot `.`
    - MUST include the service audited with the resource and a brief explanation of the result generated, e.g.: `EC2 AMI ami-0123456789 is not public.`

### Check Region

All the checks MUST fill the `report.region` with the following criteria:

- If the audited resource is regional use the `region` attribute within the resource object.
- If the audited resource is global use the `service_client.region` within the service client object.

### Resource ID, Name and ARN
All the checks MUST fill the `report.resource_id` and `report.resource_arn` with the following criteria:

- AWS
    - Resource ID -- `report.resource_id`
        - AWS Account --> Account Number `123456789012`
        - AWS Resource --> Resource ID / Name
        - Root resource --> `<root_account>`
    - Resource ARN -- `report.resource_arn`
        - AWS Account --> Root ARN `arn:aws:iam::123456789012:root`
        - AWS Resource --> Resource ARN
        - Root resource --> Resource Type ARN `f"arn:{service_client.audited_partition}:<service_name>:{service_client.region}:{service_client.audited_account}:<resource_type>"`
- GCP
    - Resource ID -- `report.resource_id`
        - GCP Resource --> Resource ID
    - Resource Name -- `report.resource_name`
        - GCP Resource --> Resource Name
- Azure
    - Resource ID -- `report.resource_id`
        - Azure Resource --> Resource ID
    - Resource Name -- `report.resource_name`
        - Azure Resource --> Resource Name

### Python Model
The following is the Python model for the check's class.

As per August 5th 2023 the `Check_Metadata_Model` can be found [here](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py#L59-L80).

```python
class Check(ABC, Check_Metadata_Model):
    """Prowler Check"""

    def __init__(self, **data):
        """Check's init function. Calls the CheckMetadataModel init."""
        # Parse the Check's metadata file
        metadata_file = (
            os.path.abspath(sys.modules[self.__module__].__file__)[:-3]
            + ".metadata.json"
        )
        # Store it to validate them with Pydantic
        data = Check_Metadata_Model.parse_file(metadata_file).dict()
        # Calls parents init function
        super().__init__(**data)

    def metadata(self) -> dict:
        """Return the JSON representation of the check's metadata"""
        return self.json()

    @abstractmethod
    def execute(self):
        """Execute the check's logic"""
```

### Using the audit config

Prowler has a [configuration file](../tutorials/configuration_file.md) which is used to pass certain configuration values to the checks, like the following:

```python title="ec2_securitygroup_with_many_ingress_egress_rules.py"
class ec2_securitygroup_with_many_ingress_egress_rules(Check):
    def execute(self):
        findings = []

        # max_security_group_rules, default: 50
        max_security_group_rules = ec2_client.audit_config.get(
            "max_security_group_rules", 50
        )
        for security_group in ec2_client.security_groups:
```

```yaml title="config.yaml"
# AWS Configuration
aws:
  # AWS EC2 Configuration

  # aws.ec2_securitygroup_with_many_ingress_egress_rules
  # The default value is 50 rules
  max_security_group_rules: 50
```

As you can see in the above code, within the service client, in this case the `ec2_client`, there is an object called `audit_config` which is a Python dictionary containing the values read from the configuration file.

In order to use it, you have to check first if the value is present in the configuration file. If the value is not present, you can create it in the `config.yaml` file and then, read it from the check.

???+ note
    It is mandatory to always use the `dictionary.get(value, default)` syntax to set a default value in the case the configuration value is not present.


## Check Metadata

Each Prowler check has metadata associated which is stored at the same level of the check's folder in a file called A `check_name.metadata.json` containing the check's metadata.

???+ note
    We are going to include comments in this example metadata JSON but they cannot be included because the JSON format does not allow comments.

```json
{
  # Provider holds the Prowler provider which the checks belongs to
  "Provider": "aws",
  # CheckID holds check name
  "CheckID": "ec2_ami_public",
  # CheckTitle holds the title of the check
  "CheckTitle": "Ensure there are no EC2 AMIs set as Public.",
  # CheckType holds Software and Configuration Checks, check more here
  # https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html#Types
  "CheckType": [
    "Infrastructure Security"
  ],
  # ServiceName holds the provider service name
  "ServiceName": "ec2",
  # SubServiceName holds the service's subservice or resource used by the check
  "SubServiceName": "ami",
  # ResourceIdTemplate holds the unique ID for the resource used by the check
  "ResourceIdTemplate": "arn:partition:service:region:account-id:resource-id",
  # Severity holds the check's severity, always in lowercase (critical, high, medium, low or informational)
  "Severity": "critical",
  # ResourceType only for AWS, holds the type from here
  # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
  "ResourceType": "Other",
  # Description holds the title of the check, for now is the same as CheckTitle
  "Description": "Ensure there are no EC2 AMIs set as Public.",
  # Risk holds the check risk if the result is FAIL
  "Risk": "When your AMIs are publicly accessible, they are available in the Community AMIs where everyone with an AWS account can use them to launch EC2 instances. Your AMIs could contain snapshots of your applications (including their data), therefore exposing your snapshots in this manner is not advised.",
  # RelatedUrl holds an URL with more information about the check purpose
  "RelatedUrl": "",
  # Remediation holds the information to help the practitioner to fix the issue in the case of the check raise a FAIL
  "Remediation": {
    # Code holds different methods to remediate the FAIL finding
    "Code": {
      # CLI holds the command in the provider native CLI to remediate it
      "CLI": "https://docs.bridgecrew.io/docs/public_8#cli-command",
      # NativeIaC holds the native IaC code to remediate it, use "https://docs.bridgecrew.io/docs"
      "NativeIaC": "",
      # Other holds the other commands, scripts or code to remediate it, use "https://www.trendmicro.com/cloudoneconformity"
      "Other": "https://docs.bridgecrew.io/docs/public_8#aws-console",
      # Terraform holds the Terraform code to remediate it, use "https://docs.bridgecrew.io/docs"
      "Terraform": ""
    },
    # Recommendation holds the recommendation for this check with a description and a related URL
    "Recommendation": {
      "Text": "We recommend your EC2 AMIs are not publicly accessible, or generally available in the Community AMIs.",
      "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/cancel-sharing-an-AMI.html"
    }
  },
  # Categories holds the category or categories where the check can be included, if applied
  "Categories": [
    "internet-exposed"
  ],
  # DependsOn is not actively used for the moment but it will hold other
  # checks wich this check is dependant to
  "DependsOn": [],
  # RelatedTo is not actively used for the moment but it will hold other
  # checks wich this check is related to
  "RelatedTo": [],
  # Notes holds additional information not covered in this file
  "Notes": ""
}
```

### Remediation Code

For the Remediation Code we use the following knowledge base to fill it:

- Official documentation for the provider
- https://docs.bridgecrew.io
- https://www.trendmicro.com/cloudoneconformity
- https://github.com/cloudmatos/matos/tree/master/remediations

### RelatedURL and Recommendation

The RelatedURL field must be filled with an URL from the provider's official documentation like https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html

Also, if not present you can use the Risk and Recommendation texts from the TrendMicro [CloudConformity](https://www.trendmicro.com/cloudoneconformity) guide.


### Python Model
The following is the Python model for the check's metadata model. We use the Pydantic's [BaseModel](https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel) as the parent class.

As per August 5th 2023 the `Check_Metadata_Model` can be found [here](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py#L34-L56).
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
    # We set the compliance to None to
    # store the compliance later if supplied
    Compliance: list = None
```
