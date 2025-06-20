# Kubernetes Provider

This page details the [Kubernetes](https://kubernetes.io/) provider implementation in Prowler.

By default, Prowler will audit all namespaces in the Kubernetes cluster accessible by the configured context. To configure it, follow the [getting started](../index.md#kubernetes) page.

## Kubernetes Provider Classes Architecture

The Kubernetes provider implementation follows the general [Provider structure](./provider.md). This section focuses on the Kubernetes-specific implementation, highlighting how the generic provider concepts are realized for Kubernetes in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md).

### `KubernetesProvider` (Main Class)

- **Location:** [`prowler/providers/kubernetes/kubernetes_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for Kubernetes-specific logic, session management, context and namespace discovery, credential validation, and configuration.
- **Key Kubernetes Responsibilities:**
    - Initializes and manages Kubernetes sessions (supports kubeconfig file or content, context selection, and namespace scoping).
    - Validates credentials and sets up the Kubernetes identity context.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Discovers accessible namespaces and cluster metadata.
    - Provides properties and methods for downstream Kubernetes service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/kubernetes/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/models.py)
- **Purpose:** Define structured data for Kubernetes identity and session info.
- **Key Kubernetes Models:**
    - `KubernetesIdentityInfo`: Holds Kubernetes identity metadata, such as context, cluster, and user.
    - `KubernetesSession`: Stores the Kubernetes API client and context information.

### `KubernetesService` (Service Base Class)

- **Location:** [`prowler/providers/kubernetes/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/lib/service/service.py)
- **Purpose:** Abstract base class that all Kubernetes service-specific classes inherit from. This implements the generic service pattern (described in [service page](./services.md#service-base-class)) specifically for Kubernetes.
- **Key Kubernetes Responsibilities:**
    - Receives a `KubernetesProvider` instance to access session, identity, and configuration.
    - Manages the Kubernetes API client and context.
    - Provides a `__threading_call__` method to make API calls in parallel by resource.
    - Exposes common audit context (`context`, `api_client`, `audit_config`, `fixer_config`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/kubernetes/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for Kubernetes-specific error handling, such as session, API, and configuration errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/kubernetes/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/lib/)
- **Purpose:** Helpers for argument parsing, mutelist management, and other cross-cutting concerns.

## Specific Patterns in Kubernetes Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the currently implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/kubernetes/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services)
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new service is following the [service implementation documentation](./services.md#adding-a-new-service) and taking other already implemented services as reference.

### Kubernetes Service Common Patterns

- Services communicate with Kubernetes using the Kubernetes Python SDK. See the [official documentation](https://github.com/kubernetes-client/python/blob/master/kubernetes/README.md/).
- Every Kubernetes service class inherits from `KubernetesService`, ensuring access to session, identity, configuration, and client utilities.
- The constructor (`__init__`) always calls `super().__init__` with the provider object, and initializes resource containers (typically as dictionaries keyed by resource UID or name).
- Resource discovery and attribute collection can be parallelized using `self.__threading_call__`.
- All Kubernetes resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes.
- Kubernetes API calls are wrapped in try/except blocks, always logging errors.
- Additional attributes that cannot be retrieved from the default call should be collected and stored for each resource using dedicated methods and threading.

## Specific Patterns in Kubernetes Checks

The Kubernetes checks pattern is described in [checks page](./checks.md). You can find all the currently implemented checks in:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/kubernetes/services/rbac/rbac_minimize_wildcard_use_roles/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services/rbac/rbac_minimize_wildcard_use_roles))
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new check is following the [Kubernetes check implementation documentation](./checks.md#creating-a-check) and taking other checks as reference.

### Check Report Class

The `Check_Report_Kubernetes` class models a single finding for a Kubernetes resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`Check_Report_Kubernetes` extends the base report structure with Kubernetes-specific fields, enabling detailed tracking of the resource, name, and namespace associated with each finding.

#### Constructor and Attribute Population

When you instantiate `Check_Report_Kubernetes`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its Kubernetes-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**:
    - Uses `resource.uid` if present.
    - Otherwise, uses `resource.name` if present.
    - Defaults to an empty string if none are available.

- **`resource_name`**:
    - Uses `resource.name` if present.
    - Defaults to an empty string if not available.

- **`namespace`**:
    - Uses `resource.namespace` if present.
    - Defaults to "cluster-wide" for cluster-scoped resources.

If the resource object does not contain the required attributes, you must set them manually in the check logic.

Other attributes are inherited from the `Check_Report` class, from which you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = Check_Report_Kubernetes(
    metadata=check_metadata,
    resource=resource_object
)
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
