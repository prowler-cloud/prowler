# Developer Guide

You can extend Prowler in many different ways, in most cases you will want to create your own checks and compliance security frameworks, here is where you can learn about how to get started with it. We also include how to create custom outputs, integrations and more.

## Get the code and install all dependencies

First of all, you need a version of Python 3.9 or higher and also pip installed to be able to install all dependencies required. Once that is satisfied go a head and clone the repo:

```
git clone https://github.com/prowler-cloud/prowler
cd prowler
```
For isolation and avoid conflicts with other environments, we recommend usage of `poetry`:
```
pip install poetry
```
Then install all dependencies including the ones for developers:
```
poetry install
poetry shell
```

## Contributing with your code or fixes to Prowler

This repo has git pre-commit hooks managed via the pre-commit tool. Install it how ever you like, then in the root of this repo run:
```
pre-commit install
```
You should get an output like the following:
```
pre-commit installed at .git/hooks/pre-commit
```

Before we merge any of your pull requests we pass checks to the code, we use the following tools and automation to make sure the code is secure and dependencies up-to-dated (these should have been already installed if you ran `pipenv install -d`):

- `bandit` for code security review.
- `safety` and `dependabot` for dependencies.
- `hadolint` and `dockle` for our containers security.
- `snyk` in Docker Hub.
- `clair` in Amazon ECR.
- `vulture`, `flake8`, `black` and `pylint` for formatting and best practices.

You can see all dependencies in file `Pipfile`.

## Create a new check for a Provider

### If the check you want to create belongs to an existing service

To create a new check, you will need to create a folder inside the specific service, i.e. `prowler/providers/<provider>/services/<service>/<check_name>/`, with the name of check following the pattern: `service_subservice_action`.
Inside that folder, create the following files:

- An empty `__init__.py`: to make Python treat this check folder as a package.
- A `check_name.py` containing the check's logic, for example:
```
# Import the Check_Report of the specific provider
from prowler.lib.check.models import Check, Check_Report_AWS
# Import the client of the specific service
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

# Create the class for the check
class ec2_ebs_volume_encryption(Check):
    def execute(self):
        findings = []
        # Iterate the service's asset that want to be analyzed
        for volume in ec2_client.volumes:
            # Initialize a Check Report for each item and assign the region, resource_id, resource_arn and resource_tags
            report = Check_Report_AWS(self.metadata())
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags
            # Make the logic with conditions and create a PASS and a FAIL with a status and a status_extended
            if volume.encrypted:
                report.status = "PASS"
                report.status_extended = f"EBS Snapshot {volume.id} is encrypted."
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS Snapshot {volume.id} is unencrypted."
            findings.append(report) # Append a report for each item

        return findings
```
- A `check_name.metadata.json` containing the check's metadata, for example:
```
{
  "Provider": "aws",
  "CheckID": "ec2_ebs_volume_encryption",
  "CheckTitle": "Ensure there are no EBS Volumes unencrypted.",
  "CheckType": [
    "Data Protection"
  ],
  "ServiceName": "ec2",
  "SubServiceName": "volume",
  "ResourceIdTemplate": "arn:partition:service:region:account-id:resource-id",
  "Severity": "medium",
  "ResourceType": "AwsEc2Volume",
  "Description": "Ensure there are no EBS Volumes unencrypted.",
  "Risk": "Data encryption at rest prevents data visibility in the event of its unauthorized access or theft.",
  "RelatedUrl": "",
  "Remediation": {
    "Code": {
      "CLI": "",
      "NativeIaC": "",
      "Other": "",
      "Terraform": ""
    },
    "Recommendation": {
      "Text": "Encrypt all EBS volumes and Enable Encryption by default You can configure your AWS account to enforce the encryption of the new EBS volumes and snapshot copies that you create. For example; Amazon EBS encrypts the EBS volumes created when you launch an instance and the snapshots that you copy from an unencrypted snapshot.",
      "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
    }
  },
  "Categories": [
    "encryption"
  ],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": ""
}
```

### If the check you want to create belongs to a service not supported already by Prowler you will need to create a new service first

To create a new service, you will need to create a folder inside the specific provider, i.e. `prowler/providers/<provider>/services/<service>/`.
Inside that folder, create the following files:

- An empty `__init__.py`: to make Python treat this service folder as a package.
- A `<service>_service.py`, containing all the service's logic and API Calls:
```
# You must import the following libraries
import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


# Create a class for the Service
################## <Service>
class <Service>:
    def __init__(self, audit_info):
        self.service = "<service>" # The name of the service boto3 client
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.<items> = [] # Create an empty list of the items to be gathered, e.g., instances
        self.__threading_call__(self.__describe_<items>__)
        self.__describe_<item>__() # Optionally you can create another function to retrieve more data about each item

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_<items>__(self, regional_client):
        """Get ALL <Service> <Items>"""
        logger.info("<Service> - Describing <Items>...")
        try:
            describe_<items>_paginator = regional_client.get_paginator("describe_<items>") # Paginator to get every item
            for page in describe_<items>_paginator.paginate():
                for <item> in page["<Items>"]:
                    if not self.audit_resources or (
                        is_resource_filtered(<item>["<item_arn>"], self.audit_resources)
                    ):
                        self.<items>.append(
                            <Item>(
                                arn=stack["<item_arn>"],
                                name=stack["<item_name>"],
                                tags=stack.get("Tags", []),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_<item>__(self):
        """Get Details for a <Service> <Item>"""
        logger.info("<Service> - Describing <Item> to get specific details...")
        try:
            for <item> in self.<items>:
                <item>_details = self.regional_clients[<item>.region].describe_<item>(
                    <Attribute>=<item>.name
                )
                # For example, check if item is Public
                <item>.public = <item>_details.get("Public", False)

        except Exception as error:
            logger.error(
                f"{<item>.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class <Item>(BaseModel):
    """<Item> holds a <Service> <Item>"""

    arn: str
    """<Items>[].Arn"""
    name: str
    """<Items>[].Name"""
    public: bool
    """<Items>[].Public"""
    tags: Optional[list] = []
    region: str

```
- A `<service>_client_.py`, containing the initialization of the service's class we have just created so the service's checks can use them:
```
from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.<service>.<service>_service import <Service>

<service>_client = <Service>(current_audit_info)
```

## Create a new security compliance framework

If you want to create or contribute with your own security frameworks or add public ones to Prowler you need to make sure the checks are available if not you have to create your own. Then create a compliance file per provider like in `prowler/compliance/aws/` and name it as `<framework>_<version>_<provider>.json` then follow the following format to create yours.

Each file version of a framework will have the following structure at high level with the case that each framework needs to be generally identified, one requirement can be also called one control but one requirement can be linked to multiple prowler checks.:

- `Framework`: string. Distinguish name of the framework, like CIS
- `Provider`: string. Provider where the framework applies, such as AWS, Azure, OCI,...
- `Version`: string. Version of the framework itself, like 1.4 for CIS.
- `Requirements`: array of objects. Include all requirements or controls with the mapping to Prowler.
- `Requirements_Id`: string. Unique identifier per each requirement in the specific framework
- `Requirements_Description`: string. Description as in the framework.
- `Requirements_Attributes`: array of objects. Includes all needed attributes per each requirement, like levels, sections, etc. Whatever helps to create a dedicated report with the result of the findings. Attributes would be taken as closely as possible from the framework's own terminology directly.
- `Requirements_Checks`: array. Prowler checks that are needed to prove this requirement. It can be one or multiple checks. In case of no automation possible this can be empty.

```
{
  "Framework": "<framework>-<provider>",
  "Version": "<version>",
  "Requirements": [
    {
      "Id": "<unique-id>",
      "Description": "Requiemente full description",
      "Checks": [
        "Here is the prowler check or checks that is going to be executed"
      ],
      "Attributes": [
        {
         <Add here your custom attributes.>
        }
      ]
    },
    ...
  ]
}
```

Finally, to have a proper output file for your reports, your framework data model has to be created in `prowler/lib/outputs/models.py` and also the CLI table output in `prowler/lib/outputs/compliance.py`.


## Create a custom output format

## Create a new integration

## Contribute with documentation

We use `mkdocs` to build this Prowler documentation site so you can easily contribute back with new docs or improving them.

1. Install `mkdocs` with your favorite package manager.
2. Inside the `prowler` repository folder run `mkdocs serve` and point your browser to `http://localhost:8000` and you will see live changes to your local copy of this documentation site.
3. Make all needed changes to docs or add new documents. To do so just edit existing md files inside `prowler/docs` and if you are adding a new section or file please make sure you add it to `mkdocs.yaml` file in the root folder of the Prowler repo.
4. Once you are done with changes, please send a pull request to us for review and merge. Thank you in advance!

## Want some swag as appreciation for your contribution?

If you are like us and you love swag, we are happy to thank you for your contribution with some laptop stickers or whatever other swag we may have at that time. Please, tell us more details and your pull request link in our [Slack workspace here](https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog). You can also reach out to Toni de la Fuente on Twitter [here](https://twitter.com/ToniBlyx), his DMs are open.
