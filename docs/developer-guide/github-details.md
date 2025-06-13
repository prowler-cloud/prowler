# GitHub Provider

This page details the [GitHub](https://github.com/) provider implementation in Prowler.

By default, Prowler will audit the GitHub account - scanning all repositories, organizations, and applications that your configured credentials can access. To configure it, follow the [getting started](../index.md#github) page.

## GitHub Provider Classes Architecture

The GitHub provider implementation follows the general [Provider structure](./provider.md). This section focuses on the GitHub-specific implementation, highlighting how the generic provider concepts are realized for GitHub in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md).

### `GithubProvider` (Main Class)

- **Location:** [`prowler/providers/github/github_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/github_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for GitHub-specific logic, session management, credential validation, and configuration.
- **Key GitHub Responsibilities:**
    - Initializes and manages GitHub sessions (supports Personal Access Token, OAuth App, and GitHub App authentication).
    - Validates credentials and sets up the GitHub identity context.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Provides properties and methods for downstream GitHub service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/github/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/models.py)
- **Purpose:** Define structured data for GitHub identity, session, and output options.
- **Key GitHub Models:**
    - `GithubSession`: Holds authentication tokens and keys for the session.
    - `GithubIdentityInfo`, `GithubAppIdentityInfo`: Store account or app identity metadata.

### `GithubService` (Service Base Class)

- **Location:** [`prowler/providers/github/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/lib/service/service.py)
- **Purpose:** Abstract base class for all GitHub service-specific classes.
- **Key GitHub Responsibilities:**
    - Receives a `GithubProvider` instance to access session, identity, and configuration.
    - Manages GitHub API clients for the authenticated user or app.
    - Exposes common audit context (`audit_config`, `fixer_config`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/github/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for GitHub-specific error handling, such as credential and session errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/github/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/lib/)
- **Purpose:** Helpers for argument parsing, mutelist management, and other cross-cutting concerns.

## Specific Patterns in GitHub Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the currently implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/github/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/github/services)
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new service is following the [service implementation documentation](./services.md#adding-a-new-service) and by taking other already implemented services as reference.

### GitHub Service Common Patterns

- Services communicate with GitHub using the PyGithub Python SDK. See the [official documentation](https://pygithub.readthedocs.io/).
- Every GitHub service class inherits from `GithubService`, ensuring access to session, identity, configuration, and client utilities.
- The constructor (`__init__`) always calls `super().__init__` with the service name and provider (e.g. `super().__init__(__class__.__name__, provider))`). Ensure that the service name in PyGithub is the same that you use in the constructor. Usually is used the `__class__.__name__` to get the service name because it is the same as the class name.
- Resource containers **must** be initialized in the constructor, typically as dictionaries keyed by resource ID or name.
- All GitHub resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes.
- GitHub API calls are wrapped in try/except blocks, always logging errors.

## Specific Patterns in GitHub Checks

The GitHub checks pattern is described in [checks page](./checks.md). You can find all the currently implemented checks in:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/github/services/repository/repository_secret_scanning_enabled/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/github/services/repository/repository_secret_scanning_enabled))
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new check is the [GitHub check implementation documentation](./checks.md#creating-a-check) and by taking other checks as reference.

### Check Report Class

The `CheckReportGithub` class models a single finding for a GitHub resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`CheckReportGithub` extends the base report structure with GitHub-specific fields, enabling detailed tracking of the resource, name, and owner associated with each finding.

#### Constructor and Attribute Population

When you instantiate `CheckReportGithub`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its GitHub-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**:
    - Uses the explicit `resource_id` argument if provided.
    - Otherwise, uses `resource.id` if present.
    - Defaults to an empty string if not available.

- **`resource_name`**:
    - Uses the explicit `resource_name` argument if provided.
    - Otherwise, uses `resource.name` if present.
    - Defaults to an empty string if not available.

- **`owner`**:
    - Uses the explicit `owner` argument if provided.
    - Otherwise, uses `resource.owner` for repositories and `resource.name` for organizations.
    - Defaults to an empty string if not available.

If the resource object does not contain the required attributes, you must set them manually in the check logic.

Other attributes are inherited from the `Check_Report` class, from which you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = CheckReportGithub(
    metadata=check_metadata,
    resource=resource_object
)
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
