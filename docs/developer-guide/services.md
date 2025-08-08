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

Once the files are create, you can check that the service has been created by running the following command: `poetry run python prowler-cli.py <provider> --list-services | grep <new_service_name>`.

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

        # Create an empty dictionary of items to be gathered, using the unique ID as the dictionary's key, e.g., instances.
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

#### Resource Models

Resource models define structured classes used within services to store and process data extracted from API calls. They are defined in the same file as the service class, but outside of the class, usually at the bottom of the file.

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

_Optimized Data Storage with Python Dictionaries_

Each group of resources within a service should be structured as a Python [dictionary](https://docs.python.org/3/tutorial/datastructures.html#dictionaries) to enable efficient lookups. The dictionary lookup operation has [O(1) complexity](https://en.wikipedia.org/wiki/Big_O_notation#Orders_of_common_functions), and lookups are constantly executed.

_Assigning Unique Identifiers_

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

Before implementing a new service, verify that Prowler's existing permissions for each provider are sufficient. If additional permissions are required, refer to the relevant documentation and update accordingly.

Provider-Specific Permissions Documentation:

- [AWS](../getting-started/requirements.md#authentication)
- [Azure](../getting-started/requirements.md#needed-permissions)
- [GCP](../getting-started/requirements.md#needed-permissions_1)
- [M365](../getting-started/requirements.md#needed-permissions_2)
- [GitHub](../getting-started/requirements.md#authentication_2)

## Service Architecture and Cross-Service Communication

### Core Principle: Service Isolation with Client Communication

Each service must contain **ONLY** the information unique to that specific service. When a check requires information from multiple services, it must use the **client objects** of other services rather than directly accessing their data structures.

This architecture ensures:

- **Loose coupling** between services
- **Clear separation of concerns**
- **Maintainable and testable code**
- **Consistent data access patterns**

### Cross-Service Communication Pattern

Instead of services directly accessing each other's internal data, checks should import and use client objects:

**❌ INCORRECT - Direct data access:**

```python
# DON'T DO THIS
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import cloudtrail_service
from prowler.providers.aws.services.s3.s3_service import s3_service

class cloudtrail_bucket_requires_mfa_delete(Check):
    def execute(self):
        # WRONG: Directly accessing service data
        for trail in cloudtrail_service.trails.values():
            for bucket in s3_service.buckets.values():
                # Direct access violates separation of concerns
```

**✅ CORRECT - Client-based communication:**

```python
# DO THIS INSTEAD
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client
from prowler.providers.aws.services.s3.s3_client import s3_client

class cloudtrail_bucket_requires_mfa_delete(Check):
    def execute(self):
        # CORRECT: Using client objects for cross-service communication
        for trail in cloudtrail_client.trails.values():
            trail_bucket = trail.s3_bucket
            for bucket in s3_client.buckets.values():
                if trail_bucket == bucket.name:
                    # Use bucket properties through s3_client
                    if bucket.mfa_delete:
                        # Implementation logic
```

### Real-World Example: CloudTrail + S3 Integration

This example demonstrates how CloudTrail checks validate S3 bucket configurations:

```python
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client
from prowler.providers.aws.services.s3.s3_client import s3_client

class cloudtrail_bucket_requires_mfa_delete(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.is_logging:
                    trail_bucket_is_in_account = False
                    trail_bucket = trail.s3_bucket

                    # Cross-service communication: CloudTrail check uses S3 client
                    for bucket in s3_client.buckets.values():
                        if trail_bucket == bucket.name:
                            trail_bucket_is_in_account = True
                            if bucket.mfa_delete:
                                report.status = "PASS"
                                report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) has MFA delete enabled."

                    # Handle cross-account scenarios
                    if not trail_bucket_is_in_account:
                        report.status = "MANUAL"
                        report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) is a cross-account bucket or out of Prowler's audit scope, please check it manually."

                    findings.append(report)
        return findings
```

**Key Benefits:**

- **CloudTrail service** only contains CloudTrail-specific data (trails, configurations)
- **S3 service** only contains S3-specific data (buckets, policies, ACLs)
- **Check logic** orchestrates between services using their public client interfaces
- **Cross-account detection** is handled gracefully when resources span accounts

### Service Consolidation Guidelines

**When to combine services in the same file:**

Implement multiple services as **separate classes in the same file** when two services are **practically the same** or one is a **direct extension** of another.

**Example: S3 and S3Control**

S3Control is an extension of S3 that provides account-level controls and access points. Both are implemented in `s3_service.py`:

```python
# File: prowler/providers/aws/services/s3/s3_service.py

class S3(AWSService):
    """Standard S3 service for bucket operations"""
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.buckets = {}
        self.regions_with_buckets = []

        # S3-specific initialization
        self._list_buckets(provider)
        self._get_bucket_versioning()
        # ... other S3-specific operations

class S3Control(AWSService):
    """S3Control service for account-level and access point operations"""
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.account_public_access_block = None
        self.access_points = {}

        # S3Control-specific initialization
        self._get_public_access_block()
        self._list_access_points()
        # ... other S3Control-specific operations
```

**Separate client files:**

```python
# File: prowler/providers/aws/services/s3/s3_client.py
from prowler.providers.aws.services.s3.s3_service import S3
s3_client = S3(Provider.get_global_provider())

# File: prowler/providers/aws/services/s3/s3control_client.py
from prowler.providers.aws.services.s3.s3_service import S3Control
s3control_client = S3Control(Provider.get_global_provider())
```

**When NOT to consolidate services:**

Keep services separate when they:

- **Operate on different resource types** (EC2 vs RDS)
- **Have different authentication mechanisms** (different API endpoints)
- **Serve different operational domains** (IAM vs CloudTrail)
- **Have different regional behaviors** (global vs regional services)

### Cross-Service Dependencies Guidelines

**1. Always use client imports:**

```python
# Correct pattern
from prowler.providers.aws.services.service_a.service_a_client import service_a_client
from prowler.providers.aws.services.service_b.service_b_client import service_b_client
```

**2. Handle missing resources gracefully:**

```python
# Handle cross-service scenarios
resource_found_in_account = False
for external_resource in other_service_client.resources.values():
    if target_resource_id == external_resource.id:
        resource_found_in_account = True
        # Process found resource
        break

if not resource_found_in_account:
    # Handle cross-account or missing resource scenarios
    report.status = "MANUAL"
    report.status_extended = "Resource is cross-account or out of audit scope"
```

**3. Document cross-service dependencies:**

```python
class check_with_dependencies(Check):
    """
    Check Description

    Dependencies:
    - service_a_client: For primary resource information
    - service_b_client: For related resource validation
    - service_c_client: For policy analysis
    """
```

## Regional Service Implementation

When implementing services for regional providers (like AWS, Azure, GCP), special considerations are needed to handle resource discovery across multiple geographic locations. This section provides a complete guide using AWS as the reference example.

### Regional vs Non-Regional Services

**Regional Services:** Require iteration across multiple geographic locations where resources may exist (e.g., EC2 instances, VPC, RDS databases).

**Non-Regional/Global Services:** Operate at a global or tenant level without regional concepts (e.g., IAM users, Route53 hosted zones).

### AWS Regional Implementation Example

AWS is the perfect example of a regional provider. Here's how Prowler handles AWS's regional architecture:


```python
# File: prowler/providers/aws/services/ec2/ec2_service.py
class EC2(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.instances = {}
        self.security_groups = {}

        # Regional resource discovery across all AWS regions
        self.__threading_call__(self._describe_instances)
        self.__threading_call__(self._describe_security_groups)

    def _describe_instances(self, regional_client):
        """Discover EC2 instances in a specific region"""
        try:
            describe_instances_paginator = regional_client.get_paginator("describe_instances")
            for page in describe_instances_paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        # Each instance includes its region
                        self.instances[instance["InstanceId"]] = Instance(
                            id=instance["InstanceId"],
                            region=regional_client.region,
                            state=instance["State"]["Name"],
                            # ... other properties
                        )
        except Exception as error:
            logger.error(f"Failed to describe instances in {regional_client.region}: {error}")
```

#### Regional Check Execution

```python
# File: prowler/providers/aws/services/ec2/ec2_instance_public_ip/ec2_instance_public_ip.py
class ec2_instance_public_ip(Check):
    def execute(self):
        findings = []

        # Automatically iterates across ALL AWS regions where instances exist
        for instance in ec2_client.instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.region = instance.region  # Critical: region attribution
            report.resource_arn = f"arn:aws:ec2:{instance.region}:{instance.account_id}:instance/{instance.id}"

            if instance.public_ip:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.id} in {instance.region} has public IP {instance.public_ip}"
            else:
                report.status = "PASS"
                report.status_extended = f"Instance {instance.id} in {instance.region} does not have a public IP"

            findings.append(report)

        return findings
```

#### Key AWS Regional Features

**Region-Specific ARNs:**

```
arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0
arn:aws:s3:eu-west-1:123456789012:bucket/my-bucket
arn:aws:rds:ap-southeast-2:123456789012:db:my-database
```

**Parallel Processing:**

- Each region processed independently in separate threads
- Failed regions don't affect other regions
- User can filter specific regions: `-f us-east-1`

**Global vs Regional Services:**

- **Regional**: EC2, RDS, VPC (require region iteration)
- **Global**: IAM, Route53, CloudFront (single `us-east-1` call)

This architecture allows Prowler to efficiently scan AWS accounts with resources spread across multiple regions while maintaining performance and error isolation.

### Regional Service Best Practices

1. **Use Threading for Regional Discovery**: Leverage the `__threading_call__` method to parallelize resource discovery across regions
2. **Store Region Information**: Always include region metadata in resource objects for proper attribution
3. **Handle Regional Failures Gracefully**: Ensure that failures in one region don't affect others
4. **Optimize for Performance**: Use paginated calls and efficient data structures for large-scale resource discovery
5. **Support Region Filtering**: Allow users to limit scans to specific regions for focused audits

## Best Practices

- When available in the provider, use threading or parallelization utilities for all methods that can be parallelized by to maximize performance and reduce scan time.
- Define a Pydantic `BaseModel` for every resource you manage, and use these models for all resource data handling.
- Log every major step (start, success, error) in resource discovery and attribute collection for traceability and debugging; include as much context as possible.
- Catch and log all exceptions, providing detailed context (region, subscription, resource, error type, line number) to aid troubleshooting.
- Use consistent naming for resource containers, unique identifiers, and model attributes to improve code readability and maintainability.
- Add docstrings to every method and comments to explain any service-specific logic, especially where provider APIs behave differently or have quirks.
- Collect and store resource tags and additional attributes to support richer checks and reporting.
- Leverage shared utility helpers for session setup, identifier parsing, and other cross-cutting concerns to avoid code duplication. This kind of code is typically stored in a `lib` folder in the service folder.
- Keep code modular, maintainable, and well-documented for ease of extension and troubleshooting.
- **Each service should contain only information unique to that specific service** - use client objects for cross-service communication.
- **Handle cross-account and missing resources gracefully** when checks span multiple services.
