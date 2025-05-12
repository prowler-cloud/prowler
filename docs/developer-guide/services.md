# Creating a New Provider Service

Here you can find how to create a new service, or to complement an existing one, for a Prowler provider.

## Introduction

In Prowler, a service represents a cloud provider solution, such as [ec2](https://aws.amazon.com/ec2/).

Each service is implemented as a class that encapsulates the required functionality for security auditing of cloud accounts.

To create a new service, a new folder must be created inside the specific provider following this pattern: `prowler/providers/<provider>/services/<new_service_name>/`.

Within this folder the following files are also to be created:

- `__init__.py` (empty) – Ensures Python recognizes this folder as a package.
- `<new_service_name>_service.py` – Contains all the logic and API calls of the service.
- `<new_service_name>_client_.py` – Contains the initialization of the freshly created service's class so that the checks can use it.

## Service

Service Structure and Initialisation  

The Prowler's service structure is as outlined below. To initialise it, just import the service client in a check.

### Service Base Class

All the Prowler provider's services inherits from a base class depending on the provider used.

- [AWS Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/service/service.py)
- [GCP Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/lib/service/service.py)
- [Azure Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/service/service.py)
- [Kubernetes Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/lib/service/service.py)

Each service class is responsible for:  
  
Initializing credentials required for authentication. Implementing threading logic where applicable. 

Note: If using threading, it must be coded here.

### Service Class

Due to the complexity and differences across cloud provider APIs, the following example demonstrates best practices for structuring a service in Prowler.

File `<new_service_name>_service.py`:

```python title="Service Class"
from datetime import datetime
from typing import Optional

# The following is just for the AWS provider.

from botocore.client import ClientError

# To use the Pydantic's BaseModel.

from pydantic import BaseModel

# Prowler logging library.

from prowler.lib.logger import logger

# Prowler resource filter, only for the AWS provider.

from prowler.lib.scan_filters.scan_filters import is_resource_filtered

# Provider parent class.

from prowler.providers.<provider>.lib.service.service import ServiceParentClass


# Create a class for the Service.

class <Service>(ServiceParentClass):
    def __init__(self, provider):
        # Call Service Parent Class __init__.
        # The __class__.__name__ is used to obtain it automatically.
        # From the Service Class name, but a custom one can be passed.
        # String in case the provider's API service name is different.
        super().__init__(__class__.__name__, provider)

        # Create an empty dictionary of items to be gathered,
        # using the unique ID as the dictionary’s key
        # e.g., instances
        self.<items> = {}

        # If parallelization can be carried out by regions or locations,
        # the function __threading_call__,
        # available in the Service Parent Class, can be used.
        self.__threading_call__(self.__describe_<items>__)

        # Optionally, another function can be created to retrieve
        # more data about each item without parallel.
        self.__describe_<item>__()

    def __describe_<items>__(self, regional_client):
        """Get ALL <Service> <Items>"""
        logger.info("<Service> - Describing <Items>...")

        # A try-except block must be created in each function.
        try:

            # Call to the provider API to retrieve the desired data.
            describe_<items>_paginator = regional_client.get_paginator("describe_<items>")

            # Paginator to get every item.
            for page in describe_<items>_paginator.paginate():

                # Another try-except within the for loop to continue iterating
                # in case something unexpected happens.
                try:

                    for <item> in page["<Items>"]:

                        # Retrieve Data for the Resource
                        #For the AWS provider the following lines must be included to retrieve
                        # data (or not) for the resource passed as argument using --resource-arn
                        if not self.audit_resources or (
                            is_resource_filtered(<item>["<item_arn>"], self.audit_resources)
                        ):
                            # Adding Retrieved Resources to the Object
                            # Once the resource has been retrieved,
                            # it must be included in the previously created object to ensure proper data handling within the service.
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

        # Logging Errors in Exception Handling
        # When handling exceptions, use the following approach to log errors appropriately based on the cloud provider being used:
        except Exception as error:
            # Fields for logging errors with relevant provider-specific attributes:
            # - AWS: Use `regional_client.region` or `self.region`
            # - GCP: Include `project_id` and `location`
            # - Azure: Utilize `subscription`

            logger.error(
                f"{<provider_specific_field>} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_<item>__(self):
        """Get Details for a <Service> <Item>"""
        logger.info("<Service> - Describing <Item> to get specific details...")

        # A try-except block must be created in each function.
        try:

            # Iterating Over Retrieved Items
            # When processing items retrieved from the previous function, loop through each one as follows:
            for <item> in self.<items>:

                # When making API calls within a loop, include a try-except block
                # to handle cases where ephemeral cloud resources may be deleted
                # during execution.
                try:
                    <item>_details = self.regional_clients[<item>.region].describe_<item>(
                        <Attribute>=<item>.name
                    )

                    # E.g., check if item is Public. This case is important: if
                    # values are being retrieved from a dictionary, the function "dict.get()"
                    # must be used with a default value in case this value is not present.
                    <item>.public = <item>_details.get("Public", False)


                # In the except block, leverage provider-specific error handling. For instance, when working with AWS, use
                # the botocore.ClientError exception to detect specific error codes:
                # raise a WARNING instead of an ERROR if some resource is not present.
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

         # Logging Errors in Exception Handling
         # When handling exceptions, use the following approach to log errors appropriately based on the cloud provider being used:
        except Exception as error:
            # Fields for logging errors with relevant provider-specific attributes:
            # - AWS: Use `regional_client.region` or `self.region`
            # - GCP: Include `project_id` and `location`
            # - Azure: Utilize `subscription`

            logger.error(
                f"{<item>.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
```

???+note To prevent false findings, when Prowler fails to retrieve items due to Access Denied or similar errors, the affected item's value is set to `None`.

#### Service Models

Service Models  

Service models define structured classes used within services to store and process data extracted from API calls.

Using Pydantic for Data Validation  

Prowler leverages Pydantic's [BaseModel](https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel) to enforce data validation.

```python title="Service Model"

# Implementation Approach

# Each service class should include custom model classes using Pydantic's BaseModel for the resources being audited.

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

    # Optional attributes can be created set to None by default.
    
    tags: Optional[list]
     """<Items>[].tags"""
```

#### Service Objects

Optimized Data Storage with Python Dictionaries  

Each group of resources within a service should be structured as a Python [dictionary](https://docs.python.org/3/tutorial/datastructures.html#dictionaries) to enable efficient lookups. The dictionary lookup operation has [O(1) complexity](https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions), and lookups are constantly executed.

Assigning Unique Identifiers  

Each dictionary key must be a unique ID, such as a resource Unique ID or Amazon Resource Name (ARN).

Example:

```python
self.vpcs = {}
self.vpcs["vpc-01234567890abcdef"] = VPC_Object_Class()
```

### Service Client

Each Prowler service requires a service client to use the service in the checks.

The following is the `<new_service_name>_client.py` file, which contains the initialization of the freshly created service's class so that service checks can use it:

```python
from prowler.providers.common.provider import Provider
from prowler.providers.<provider>.services.<new_service_name>.<new_service_name>_service import <Service>

<new_service_name>_client = <Service>(Provider.get_global_provider())
```

## Provider Permissions in Prowler

Before implementing a new service, verify that Prowler’s existing permissions for each provider are sufficient. If additional permissions are required, refer to the relevant documentation and update accordingly.  
  
Provider-Specific Permissions Documentation:

- AWS: https://docs.prowler.cloud/en/latest/getting-started/requirements/#aws-authentication
- Azure: https://docs.prowler.cloud/en/latest/getting-started/requirements/#permissions
- GCP: https://docs.prowler.cloud/en/latest/getting-started/requirements/#gcp-authentication
- Microsoft365: https://docs.prowler.cloud/en/latest/getting-started/requirements/#microsoft365-authentication