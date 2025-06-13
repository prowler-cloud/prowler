# AWS Provider

In this page you can find all the details about [Amazon Web Services (AWS)](https://aws.amazon.com/) provider implementation in Prowler.

By default, Prowler will audit just one account and organization settings per scan. To configure it, follow the [getting started](../index.md#aws) page.

## AWS Provider Classes Architecture

The AWS provider implementation follows the general [Provider structure](./provider.md). This section focuses on the AWS-specific implementation, highlighting how the generic provider concepts are realized for AWS in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md). In next subsection you can find a list of the main classes of the AWS provider.

### `AwsProvider` (Main Class)

- **Location:** [`prowler/providers/aws/aws_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for AWS-specific logic, session management, credential validation, role assumption, region and organization discovery, and configuration.
- **Key AWS Responsibilities:**
    - Initializes and manages AWS sessions (with or without role assumption, MFA, etc.).
    - Validates credentials and sets up the AWS identity context.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Discovers enabled AWS regions and organization metadata.
    - Provides properties and methods for downstream AWS service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/aws/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/models.py)
- **Purpose:** Define structured data for AWS identity, session, credentials, organization info, and more.
- **Key AWS Models:**
    - `AWSOrganizationsInfo`: Holds AWS Organizations metadata, to be used by the checks.
    - `AWSCredentials`, `AWSAssumeRoleInfo`, `AWSAssumeRoleConfiguration`: Used for role assumption and session management.
    - `AWSIdentityInfo`: Stores account, user, partition, and region context for the scan.
    - `AWSSession`: Wraps the current and original [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) sessions and config.

### `AWSService` (Service Base Class)

- **Location:** [`prowler/providers/aws/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/service/service.py)
- **Purpose:** Abstract base class that all AWS service-specific classes inherit from. This implements the generic service pattern (described in [service page](./services.md#service-base-class)) specifically for AWS.
- **Key AWS Responsibilities:**
    - Receives an `AwsProvider` instance to access session, identity, and configuration.
    - Manages clients for all services by regions.
    - Provides `__threading_call__` method to make boto3 calls in parallel. By default, this calls are made by region, but it can be overridden with the first parameter of the method and use by resource.
    - Exposes common audit context (`audited_account`, `audited_account_arn`, `audited_partition`, `audited_resources`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/aws/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for AWS-specific error handling, such as credential and role errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/aws/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/)
- **Purpose:** Helpers for session setup, ARN parsing, mutelist management, and other cross-cutting concerns.

## Specific Patterns in AWS Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the right now implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/aws/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services)
- In the [Prowler Hub](https://hub.prowler.com/). For a more human-readable view.

The best reference to understand how to implement a new service is following the [service implementation documentation](./services.md#adding-a-new-service) and taking other services already implemented as reference. In next subsection you can find a list of common patterns that are used accross all AWS services.

### AWS Service Common Patterns

- Services communicate with AWS using boto3, you can find the documentation with all the services [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/index.html).
- Every AWS service class inherits from `AWSService`, ensuring access to session, identity, configuration, and threading utilities.
- The constructor (`__init__`) always calls `super().__init__` with the service name and provider (e.g. `super().__init__(__class__.__name__, provider))`). Ensure that the service name in boto3 is the same that you use in the constructor. Usually is used the `__class__.__name__` to get the service name because it is the same as the class name.
- Resource containers **must** be initialized in the constructor. They should be dictionaries, with the key being the resource ARN or equivalent unique identifier and the value being the resource object.
- Resource discovery and attribute collection are parallelized using `self.__threading_call__`, typically by region or resource, for performance. The first parameter of the method is the iterator, if not provided, it will be the region; but if present indicate an array of the resources to be processed.
- Resource filtering is consistently enforced using `self.audit_resources` attribute and `is_resource_filtered` function, it is used to see if user has provided some resource that is not in the audit scope, so we can skip it in the service logic. Normally it is used befor storing the resource in the service container as follows: `if not self.audit_resources or (is_resource_filtered(resource["arn"], self.audit_resources)):`.
- All AWS resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes.
- AWS API calls are wrapped in try/except blocks, with specific handling for `ClientError` and generic exceptions, always logging errors.
- If ARN is not present for some resource, it can be constructed using string interpolation, always including partition, service, region, account, and resource ID.
- Tags and additional attributes that cannot be retrieved from the default call, should be collected and stored for each resource using dedicated methods and threading using the resource object list as iterator.

## Specific Patterns in AWS Checks

The AWS checks pattern is described in [checks page](./checks.md). You can find all the right now implemented checks:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/aws/services/s3/s3_bucket_acl_prohibited/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services/s3/s3_bucket_acl_prohibited))
- In the [Prowler Hub](https://hub.prowler.com/). For a more human-readable view.

The best reference to understand how to implement a new check is following the [check creation documentation](./checks.md#creating-a-check) and taking other similar checks as reference.

### Check Report Class

The `Check_Report_AWS` class models a single finding for an AWS resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`Check_Report_AWS` extends the base report structure with AWS-specific fields, enabling detailed tracking of the resource, ARN, and region associated with each finding.

#### Constructor and Attribute Population

When you instantiate `Check_Report_AWS`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its AWS-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**:
    - Uses `resource.id` if present.
    - Otherwise, uses `resource.name` if present.
    - Defaults to an empty string if none are available.

- **`resource_arn`**:
    - Uses `resource.arn` if present.
    - Defaults to an empty string if ARN is not present in the resource object.

- **`region`**:
    - Uses `resource.region` if present.
    - Defaults to an empty string if region is not present in the resource object.

If the resource object does not contain the required attributes, you must set them manually in the check logic.

Other attributes are inherited from the `Check_Report` class, from that ones you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = Check_Report_AWS(
    metadata=check_metadata,
    resource=resource_object
)
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
