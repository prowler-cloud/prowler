# Create a new Provider Service

Here you can find how to create a new service, or to complement an existing one, for a Prowler Provider.

## Introduction

In Prowler, a service is basically a solution that is offered by a cloud provider i.e. [ec2](https://aws.amazon.com/ec2/). Essentially it is a class that stores all the necessary stuff that we will need later in the checks to audit some aspects of our Cloud account.

To create a new service, you will need to create a folder inside the specific provider, i.e. `prowler/providers/<provider>/services/<new_service_name>/`.

Inside that folder, you MUST create the following files:

- An empty `__init__.py`: to make Python treat this service folder as a package.
- A `<new_service_name>_service.py`, containing all the service's logic and API calls.
- A `<new_service_name>_client_.py`, containing the initialization of the service's class we have just created so the checks's checks can use it.

## Service

The Prowler's service structure is the following and the way to initialise it is just by importing the service client in a check.

### Service Base Class

All the Prowler provider's services inherits from a base class depending on the provider used.

- [AWS Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/service/service.py)
- [GCP Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/lib/service/service.py)
- [Azure Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/service/service.py)
- [Kubernetes Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/lib/service/service.py)

Each class is used to initialize the credentials and the API's clients to be used in the service. If some threading is used it must be coded there.

### Service Class

Due to the complexity and differences of each provider API we are going to use an example service to guide you in how can it be created.

The following is the `<new_service_name>_service.py` file:

```python title="Service Class"
from datetime import datetime
from typing import Optional

# The following is just for the AWS provider
from botocore.client import ClientError

# To use the Pydantic's BaseModel
from pydantic import BaseModel

# Prowler logging library
from prowler.lib.logger import logger

# Prowler resource filter, only for the AWS provider
from prowler.lib.scan_filters.scan_filters import is_resource_filtered

# Provider parent class
from prowler.providers.<provider>.lib.service.service import ServiceParentClass


# Create a class for the Service
################## <Service>
class <Service>(ServiceParentClass):
    def __init__(self, provider):
        # Call Service Parent Class __init__
        # We use the __class__.__name__ to get it automatically
        # from the Service Class name but you can pass a custom
        # string if the provider's API service name is different
        super().__init__(__class__.__name__, provider)

        # Create an empty dictionary of items to be gathered,
        # using the unique ID as the dictionary key
        # e.g., instances
        self.<items> = {}

        # If you can parallelize by regions or locations
        # you can use the __threading_call__ function
        # available in the Service Parent Class
        self.__threading_call__(self.__describe_<items>__)

        # Optionally you can create another function to retrieve
        # more data about each item without parallel
        self.__describe_<item>__()

    def __describe_<items>__(self, regional_client):
        """Get ALL <Service> <Items>"""
        logger.info("<Service> - Describing <Items>...")

        # We MUST include a try/except block in each function
        try:

            # Call to the provider API to retrieve the data we want
            describe_<items>_paginator = regional_client.get_paginator("describe_<items>")

            # Paginator to get every item
            for page in describe_<items>_paginator.paginate():

                # Another try/except within the loop for to continue looping
                # if something unexpected happens
                try:

                    for <item> in page["<Items>"]:

                        # For the AWS provider we MUST include the following lines to retrieve
                        # or not data for the resource passed as argument using the --resource-arn
                        if not self.audit_resources or (
                            is_resource_filtered(<item>["<item_arn>"], self.audit_resources)
                        ):
                            # Then we have to include the retrieved resource in the object
                            # previously created
                            self.<items>[<item_unique_id>] =
                                <Item>(
                                    arn=stack["<item_arn>"],
                                    name=stack["<item_name>"],
                                    tags=stack.get("Tags", []),
                                    region=regional_client.region,
                                )

                except Exception as error:
                    logger.error(
                        f"{<provider_specific_field>} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        # In the except part we have to use the following code to log the errors
        except Exception as error:
            # Depending on each provider we can use the following fields in the logger:
            # - AWS: regional_client.region or self.region
            # - GCP: project_id and location
            # - Azure: subscription

            logger.error(
                f"{<provider_specific_field>} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_<item>__(self):
        """Get Details for a <Service> <Item>"""
        logger.info("<Service> - Describing <Item> to get specific details...")

        # We MUST include a try/except block in each function
        try:

            # Loop over the items retrieved in the previous function
            for <item> in self.<items>:

                # When we perform calls to the Provider API within a for loop we have
                # to include another try/except block because in the cloud there are
                # ephemeral resources that can be deleted at the time we are checking them
                try:
                    <item>_details = self.regional_clients[<item>.region].describe_<item>(
                        <Attribute>=<item>.name
                    )

                    # For example, check if item is Public. Here is important if we are
                    # getting values from a dictionary we have to use the "dict.get()"
                    # function with a default value in the case this value is not present
                    <item>.public = <item>_details.get("Public", False)


                # In this except block, for example for the AWS Provider we can use
                # the botocore.ClientError exception and check for a specific error code
                # to raise a WARNING instead of an ERROR if some resource is not present.
                except ClientError as error:
                    if error.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                        logger.warning(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{<provider_specific_field>} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    continue

         # In the except part we have to use the following code to log the errors
        except Exception as error:
            # Depending on each provider we can use the following fields in the logger:
            # - AWS: regional_client.region or self.region
            # - GCP: project_id and location
            # - Azure: subscription

            logger.error(
                f"{<item>.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
```
???+note
    To avoid fake findings, when Prowler can't retrieve the items, because an Access Denied or similar error, we set that items value as `None`.

#### Service Models

Service models are classes that are used in the service to design all that we need to store in each class object extrated from API calls. We use the Pydantic's [BaseModel](https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel) to take advantage of the data validation.

```python title="Service Model"
# In each service class we have to create some classes using
# the Pydantic's Basemodel for the resources we want to audit.
class <Item>(BaseModel):
    """<Item> holds a <Service> <Item>"""

    arn: str
    """<Items>[].arn"""

    name: str
    """<Items>[].name"""

    region: str
    """<Items>[].region"""

    public: bool
    """<Items>[].public"""

    # We can create Optional attributes set to None by default
    tags: Optional[list]
     """<Items>[].tags"""
```
#### Service Objects
In the service each group of resources should be created as a Python [dictionary](https://docs.python.org/3/tutorial/datastructures.html#dictionaries). This is because we are performing lookups all the time and the Python dictionary lookup has [O(1) complexity](https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions).

We MUST set as the dictionary key a unique ID, like the resource Unique ID or ARN.

Example:
```python
self.vpcs = {}
self.vpcs["vpc-01234567890abcdef"] = VPC_Object_Class()
```

### Service Client

Each Prowler service requires a service client to use the service in the checks.

The following is the `<new_service_name>_client.py` containing the initialization of the service's class we have just created so the service's checks can use them:

```python
from prowler.providers.common.provider import Provider
from prowler.providers.<provider>.services.<new_service_name>.<new_service_name>_service import <Service>

<new_service_name>_client = <Service>(Provider.get_global_provider())
```

## Permissions

It is really important to check if the current Prowler's permissions for each provider are enough to implement a new service. If we need to include more please refer to the following documentaion and update it:

- AWS: https://docs.prowler.cloud/en/latest/getting-started/requirements/#aws-authentication
- Azure: https://docs.prowler.cloud/en/latest/getting-started/requirements/#permissions
- GCP: https://docs.prowler.cloud/en/latest/getting-started/requirements/#gcp-authentication
