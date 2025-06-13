# Prowler Services

Here you can find how to create a new service, or to complement an existing one, for a [Prowler Provider](./provider.md).

???+note
    First ensure that the provider you want to add the service is already created. It can be checked [here](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers). If the provider is not present, please refer to the [Provider](./provider.md) documentation to create it from scratch.

## Introduction

In Prowler, a **service** represents a specific solution or resource offered by one of the supported [Prowler Providers](./provider.md), for example, [EC2](https://aws.amazon.com/ec2/) in AWS, or [Microsoft Exchange](https://www.microsoft.com/en-us/microsoft-365/exchange/exchange-online) in M365. Services are the building blocks that allow Prowler interact directly with the various resources exposed by each provider.

Each service is implemented as a class that encapsulates all the logic, data models, and API interactions required to gather and store information about that service's resources. All of this data is used by the [Prowler checks](./checks.md) to generate the security findings.

## Adding a New Service

To create a new service, a new folder must be created inside the specific provider following this pattern: `prowler/providers/<provider>/services/<new_service_name>/`.

Within this folder the following files are also to be created:

- `__init__.py` (empty) – Ensures Python recognizes this folder as a package.
- `<new_service_name>_service.py` – Contains all the logic and API calls of the service.
- `<new_service_name>_client_.py` – Contains the initialization of the freshly created service's class so that the checks can use it.

## Service Structure and Initialisation

The Prowler's service structure is as outlined below. To initialise it, just import the service client in a check.

### Service Base Class

All Prowler provider service should inherit from a common base class to avoid code duplication. This base class handles initialization and storage of functions and objects needed across services. The exact implementation depends on the provider's API requirements, but the following are the most common responsibilities:

- Initialize/store clients to interact with the provider's API.
- Store the audit and fixer configuration.
- Implement threading logic where applicable.

For reference, the base classes for each provider can be checked here:

- [AWS Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/service/service.py)
- [GCP Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/lib/service/service.py)
- [Azure Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/service/service.py)
- [Kubernetes Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/lib/service/service.py)
- [M365 Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/lib/service/service.py)
- [GitHub Service Base Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/lib/service/service.py)

### Service Class

Due to the complexity and differences across provider APIs, the following example demonstrates best practices for structuring a service in Prowler.

File `<new_service_name>_service.py`:

```python title="Example Service Class"
from datetime import datetime
from typing import Optional

# To use the Pydantic's BaseModel.
from pydantic import BaseModel

# Prowler logging library.
from prowler.lib.logger import logger

# Provider parent class.
from prowler.providers.<provider>.lib.service.service import ServiceParentClass

# Create a class for the Service.
class <Service>(ServiceParentClass):
    def __init__(self, provider: Provider):
        """Initialize the Service Class

        Args:
            provider: Prowler Provider object.
        """
        # Call Service Parent Class __init__.
        # The __class__.__name__ is used to obtain it automatically.
        # From the Service Class name, but a custom one can be passed.
        # String in case the provider's API service name is different.
        super().__init__(__class__.__name__, provider)

        # Create an empty dictionary of items to be gathered, using the unique ID as the dictionary’s key, e.g., instances.
        self.<items> = {}

        # If parallelization can be carried out by regions or locations, the function __threading_call__ to be used must be implemented in the Service Parent Class.
        # If it is not implemented, you can make it in a sequential way, just calling the function.
        self.__threading_call__(self.__describe_<items>__)

        # If it is needed you can create another function to retrieve more data from the items.
        # Here we are using the second parameter of the __threading_call__ function to create one thread per item.
        # You can also make it sequential without using the __threading_call__ function iterating over the items inside the function.
        self.__threading_call__(self.__describe_<item>__, self.<items>.values())

    # In case of use the __threading_call__ function, you have to pass the regional_client to the function, as a parameter.
    def __describe_<items>__(self, regional_client):
        """Get all <items> and store in the self.<items> dictionary

        Args:
            regional_client: Regional client object.
        """
        logger.info("<Service> - Describing <Items>...")

        # A try-except block must be created in each function.
        try:
            # If pagination is supported by the provider, is always better to use it, call to the provider API to retrieve the desired data.
            describe_<items>_paginator = regional_client.get_paginator("describe_<items>")

            # Paginator to get every item.
            for page in describe_<items>_paginator.paginate():

                # Another try-except within the for loop to continue iterating in case something unexpected happens.
                try:

                    for <item> in page["<Items>"]:

                        # Adding Retrieved Resources to the Object

                        # Once the resource has been retrieved, it must be included in the previously created object to ensure proper data handling within the service.
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
            # Depending on each provider we can must use different fields in the logger, e.g.: AWS: regional_client.region or self.region, GCP: project_id and location, Azure: subscription
            logger.error(
                f"{<provider_specific_field>} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_<item>__(self, item: <Item>):
        """Get details for a <item>

        Args:
            item: Item object.
        """
        logger.info("<Service> - Describing <Item> to get specific details...")
        # A try-except block must be created in each function.
        try:

            <item>_details = self.regional_clients[<item>.region].describe_<item>(
                <Attribute>=<item>.name
            )

            # E.g., check if item is Public. This case is important: if values are being retrieved from a dictionary, the function "dict.get()" must be used with a default value in case this value is not present.
            <item>.public = <item>_details.get("Public", False)
        except Exception as error:
            # Fields for logging errors with relevant item information, e.g.: AWS: <item>.region, GCP: <item>.project_id, Azure: <item>.region
            logger.error(
                f"{<item>.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
```

???+note
    To prevent false findings, when Prowler fails to retrieve items due to Access Denied or similar errors, the affected item's value is set to `None`.

#### Service Models

Service models define structured classes used within services to store and process data extracted from API calls.

Using Pydantic for Data Validation

Prowler leverages Pydantic's [BaseModel](https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel) to enforce data validation.

```python title="Service Model"

# Implementation Approach

# Each service class should include custom model classes using Pydantic's BaseModel for the resources being audited.

class <Item>(BaseModel):
    """<Item> holds a <Service> <Item>"""

    id: str
    """<Items>[].id"""

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

#### Service Attributes

*Optimized Data Storage with Python Dictionaries*

Each group of resources within a service should be structured as a Python [dictionary](https://docs.python.org/3/tutorial/datastructures.html#dictionaries) to enable efficient lookups. The dictionary lookup operation has [O(1) complexity](https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions), and lookups are constantly executed.

*Assigning Unique Identifiers*

Each dictionary key must be a unique ID to identify the resource in a univocal way.

Example:

```python
self.virtual_machines = {}
self.virtual_machines["vm-01234567890abcdef"] = VirtualMachine()
```

### Service Client

Each Prowler service requires a service client to use the service in the checks.

The following is the `<new_service_name>_client.py` file, which contains the initialization of the freshly created service's class so that service checks can use it. This file is almost the same for all the services among the providers:

```python
from prowler.providers.common.provider import Provider
from prowler.providers.<provider>.services.<new_service_name>.<new_service_name>_service import <Service>

<new_service_name>_client = <Service>(Provider.get_global_provider())
```

## Provider Permissions in Prowler

Before implementing a new service, verify that Prowler’s existing permissions for each provider are sufficient. If additional permissions are required, refer to the relevant documentation and update accordingly.

Provider-Specific Permissions Documentation:

- [AWS](../getting-started/requirements.md#authentication)
- [Azure](../getting-started/requirements.md#needed-permissions)
- [GCP](../getting-started/requirements.md#needed-permissions_1)
- [M365](../getting-started/requirements.md#needed-permissions_2)
