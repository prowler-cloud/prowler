# Google Cloud Provider

This page details the [Google Cloud Platform (GCP)](https://cloud.google.com/) provider implementation in Prowler.

By default, Prowler will audit all the GCP projects that the authenticated identity can access. To configure it, follow the [getting started](../index.md#google-cloud) page.

## GCP Provider Classes Architecture

The GCP provider implementation follows the general [Provider structure](./provider.md). This section focuses on the GCP-specific implementation, highlighting how the generic provider concepts are realized for GCP in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md).

### Main Class

- **Location:** [`prowler/providers/gcp/gcp_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for GCP-specific logic, session management, credential validation, project and organization discovery, and configuration.
- **Key GCP Responsibilities:**
    - Initializes and manages GCP sessions (supports Application Default Credentials, Service Account, OAuth, and impersonation).
    - Validates credentials and sets up the GCP identity context.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Discovers accessible GCP projects and organization metadata.
    - Provides properties and methods for downstream GCP service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/gcp/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/models.py)
- **Purpose:** Define structured data for GCP identity, project, and organization info.
- **Key GCP Models:**
    - `GCPIdentityInfo`: Holds GCP identity metadata, such as the profile name.
    - `GCPOrganization`: Represents a GCP organization with ID, name, and display name.
    - `GCPProject`: Represents a GCP project with number, ID, name, organization, labels, and lifecycle state.

### `GCPService` (Service Base Class)

- **Location:** [`prowler/providers/gcp/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/lib/service/service.py)
- **Purpose:** Abstract base class that all GCP service-specific classes inherit from. This implements the generic service pattern (described in [service page](./services.md#service-base-class)) specifically for GCP.
- **Key GCP Responsibilities:**
    - Receives a `GcpProvider` instance to access session, identity, and configuration.
    - Manages clients for all services by project.
    - Filters projects to only those with the relevant API enabled.
    - Provides `__threading_call__` method to make API calls in parallel by project or resource.
    - Exposes common audit context (`project_ids`, `projects`, `default_project_id`, `audit_config`, `fixer_config`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/gcp/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for GCP-specific error handling, such as credential, session, and project access errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/gcp/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/lib/)
- **Purpose:** Helpers for argument parsing, mutelist management, and other cross-cutting concerns.

## Specific Patterns in GCP Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the currently implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/gcp/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/gcp/services)
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new service is following the [service implementation documentation](./services.md#adding-a-new-service) and taking other services already implemented as reference. In next subsection you can find a list of common patterns that are used accross all GCP services.

### GCP Service Common Patterns

- Services communicate with GCP using the Google Cloud Python SDK, you can find the documentation with all the services [here](https://cloud.google.com/python/docs/reference).
- Every GCP service class inherits from `GCPService`, ensuring access to session, identity, configuration, and client utilities.
- The constructor (`__init__`) always calls `super().__init__` with the service name, provider, region (default "global"), and API version (default "v1"). Usually, the service name is the class name in lowercase, so it is called like `super().__init__(__class__.__name__, provider)`.
- Resource containers **must** be initialized in the constructor, typically as dictionaries keyed by resource ID and the value is the resource object.
- Only projects with the API enabled are included in the audit scope.
- Resource discovery and attribute collection can be parallelized using `self.__threading_call__`, typically by region/zone or resource.
- All GCP resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes.
- Each GCP API calls are wrapped in try/except blocks, always logging errors.
- Tags and additional attributes that cannot be retrieved from the default call should be collected and stored for each resource using dedicated methods and threading.

## Specific Patterns in GCP Checks

The GCP checks pattern is described in [checks page](./checks.md). You can find all the currently implemented checks:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/gcp/services/iam/iam_sa_user_managed_key_unused/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/gcp/services/iam/iam_sa_user_managed_key_unused))
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new check is following the [GCP check implementation documentation](./checks.md#creating-a-check) and taking other similar checks as reference.

### Check Report Class

The `Check_Report_GCP` class models a single finding for a GCP resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`Check_Report_GCP` extends the base report structure with GCP-specific fields, enabling detailed tracking of the resource, project, and location associated with each finding.

#### Constructor and Attribute Population

When you instantiate `Check_Report_GCP`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its GCP-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**:
    - Uses the explicit `resource_id` argument if provided.
    - Otherwise, uses `resource.id` if present.
    - Otherwise, uses `resource.name` if present.
    - Defaults to an empty string if none are available.

- **`resource_name`**:
    - Uses the explicit `resource_name` argument if provided.
    - Otherwise, uses `resource.name` if present.
    - Defaults to an empty string.

- **`project_id`**:
    - Uses the explicit `project_id` argument if provided.
    - Otherwise, uses `resource.project_id` if present.
    - Defaults to an empty string.

- **`location`**:
    - Uses the explicit `location` argument if provided.
    - Otherwise, uses `resource.location` if present.
    - Otherwise, uses `resource.region` if present.
    - Defaults to "global" if none are available.

All these attributes can be overridden by passing the corresponding argument to the constructor. If the resource object does not contain the required attributes, you must set them manually.
Others attributes are inherited from the `Check_Report` class, from that ones you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = Check_Report_GCP(
    metadata=check_metadata,
    resource=resource_object,
    resource_id="custom-id",  # Optional override
    resource_name="custom-name",  # Optional override
    project_id="my-gcp-project",  # Optional override
    location="us-central1"  # Optional override
)
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
