# Azure Provider

In this page you can find all the details about [Microsoft Azure](https://azure.microsoft.com/) provider implementation in Prowler.

By default, Prowler will audit all the subscriptions that it is able to list in the Microsoft Entra tenant, and tenant Entra ID service. To configure it, follow the [getting started](../index.md#azure) page.

## Azure Provider Classes Architecture

The Azure provider implementation follows the general [Provider structure](./provider.md). This section focuses on the Azure-specific implementation, highlighting how the generic provider concepts are realized for Azure in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md). In next subsection you can find a list of the main classes of the Azure provider.

### `AzureProvider` (Main Class)

- **Location:** [`prowler/providers/azure/azure_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for Azure-specific logic, session management, credential validation, and configuration.
- **Key Azure Responsibilities:**
    - Initializes and manages Azure sessions (supports Service Principal, CLI, Browser, and Managed Identity authentication).
    - Validates credentials and sets up the Azure identity context.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Retrieves subscription(s) metadata.
    - Provides properties and methods for downstream Azure service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/azure/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/models.py)
- **Purpose:** Define structured data for Azure identity, session, region configuration, and subscription info.
- **Key Azure Models:**
    - `AzureIdentityInfo`: Holds Azure identity metadata, including tenant ID, domain, subscription names and IDs, and locations.
    - `AzureRegionConfig`: Stores the specific region that will be audited. That can be: Global, US Government or China.
    - `AzureSubscription`: Represents a subscription with ID, display name, and state.

### `AzureService` (Service Base Class)

- **Location:** [`prowler/providers/azure/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/service/service.py)
- **Purpose:** Abstract base class that all Azure service-specific classes inherit from. This implements the generic service pattern (described in [service page](./services.md#service-base-class)) specifically for Azure.
- **Key Azure Responsibilities:**
    - Receives an `AzureProvider` instance to access session, identity, and configuration.
    - Manages clients for all services by subscription.
    - Exposes common audit context (`subscriptions`, `locations`, `audit_config`, `fixer_config`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/azure/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for Azure-specific error handling, such as credential, region, and session errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/azure/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/)
- **Purpose:** Helpers for argument parsing, region setup, mutelist management, and other cross-cutting concerns.

## Specific Patterns in Azure Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the currently implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/azure/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services)
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new service is following the [service implementation documentation](./services.md#adding-a-new-service) and taking other services already implemented as reference. In next subsection you can find a list of common patterns that are used accross all Azure services.

### Azure Service Common Patterns

- Services communicate with Azure using the Azure Python SDK, mainly using the Azure Management Client (except for the Microsoft Entra ID service, that is using the Microsoft Graph API), you can find the documentation with all the management services [here](https://learn.microsoft.com/en-us/python/api/overview/azure/?view=azure-python).
- Every Azure service class inherits from `AzureService`, ensuring access to session, identity, configuration, and client utilities.
- The constructor (`__init__`) always calls `super().__init__` with the service Azure Management Client and Prowler provider object (e.g `super().__init__(WebSiteManagementClient, provider)`).
- Resource containers **must** be initialized in the constructor, and they should be dictionaries, with the key being the subscription ID, the value being a dictionary with the resource ID as key and the resource object as value.
- All Azure resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes. Some are represented as dataclasses due to legacy reasons, but new resources should be represented as Pydantic `BaseModel` classes.
- Azure SDK functions are wrapped in try/except blocks, with specific handling for errors, always logging errors. It is a best practice to create a custom function for every Azure SDK call, in that way we can handle the errors in a more specific way.

## Specific Patterns in Azure Checks

The Azure checks pattern is described in [checks page](./checks.md). You can find all the currently implemented checks:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/azure/services/storage/storage_blob_public_access_level_is_disabled/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/storage/storage_blob_public_access_level_is_disabled))
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new check is the [Azure check implementation documentation](./checks.md#creating-a-check) and taking other similar checks as reference.

### Check Report Class

The `Check_Report_Azure` class models a single finding for an Azure resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`Check_Report_Azure` extends the base report structure with Azure-specific fields, enabling detailed tracking of the resource, resource ID, name, subscription, and location associated with each finding.

#### Constructor and Attribute Population

When you instantiate `Check_Report_Azure`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its Azure-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**:
    - Uses `resource.id` if present.
    - Otherwise, uses `resource.resource_id` if present.
    - Defaults to an empty string if not available.

- **`resource_name`**:
    - Uses `resource.name` if present.
    - Otherwise, uses `resource.resource_name` if present.
    - Defaults to an empty string if not available.

- **`subscription`**:
    - Defaults to an empty string, it **must** be set in the check logic.

- **`location`**:
    - Uses `resource.location` if present.
    - Defaults to an empty string if not available.

If the resource object does not contain the required attributes, you must set them manually in the check logic.

Other attributes are inherited from the `Check_Report` class, from which you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = Check_Report_Azure(
    metadata=check_metadata,
    resource=resource_object
)
report.subscription = subscription_id
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
