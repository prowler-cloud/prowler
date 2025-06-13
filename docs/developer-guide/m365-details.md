# Microsoft 365 (M365) Provider

This page details the [Microsoft 365 (M365)](https://www.microsoft.com/en-us/microsoft-365) provider implementation in Prowler.

By default, Prowler will audit the Microsoft Entra ID tenant and its supported services. To configure it, follow the [getting started](../index.md#microsoft-365) page.

---

## PowerShell Requirements for M365 Checks

> **Most Microsoft 365 checks in Prowler require PowerShell, not just the Microsoft Graph API.**

- **PowerShell is essential** for retrieving data from Exchange Online, Teams, Defender, Purview, and other M365 services. Many checks cannot be performed using only the Graph API.
- **PowerShell 7.4 or higher is required** (7.5 recommended). PowerShell 5.1 and earlier versions are not supported for M365 checks.
- **Required modules:**
    - [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.6.0) (≥ 3.6.0)
    - [MicrosoftTeams](https://www.powershellgallery.com/packages/MicrosoftTeams/6.6.0) (≥ 6.6.0)
- If you use Prowler Cloud or the official containers, PowerShell is pre-installed. For local or pip installations, you must install PowerShell and the modules yourself. See [Requirements: Supported PowerShell Versions](../getting-started/requirements.md#supported-powershell-versions) and [Needed PowerShell Modules](../getting-started/requirements.md#needed-powershell-modules).
- For more details and troubleshooting, see [Use of PowerShell in M365](../tutorials/microsoft365/use-of-powershell.md).

---

## M365 Provider Classes Architecture

The M365 provider implementation follows the general [Provider structure](./provider.md). This section focuses on the M365-specific implementation, highlighting how the generic provider concepts are realized for M365 in Prowler. For a full overview of the provider pattern, base classes, and extension guidelines, see [Provider documentation](./provider.md).

### `M365Provider` (Main Class)

- **Location:** [`prowler/providers/m365/m365_provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/m365_provider.py)
- **Base Class:** Inherits from `Provider` (see [base class details](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py)).
- **Purpose:** Central orchestrator for M365-specific logic, session management, credential validation, region/authority configuration, and identity context.
- **Key M365 Responsibilities:**
    - Initializes and manages M365 sessions (supports Service Principal, environment variables, Azure CLI, browser, and user/password authentication).
    - Validates credentials and sets up the M365 identity context.
    - Manages the Microsoft Graph API client and the PowerShell client.
    - Loads and manages configuration, mutelist, and fixer settings.
    - Provides properties and methods for downstream M365 service classes to access session, identity, and configuration data.

### Data Models

- **Location:** [`prowler/providers/m365/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/models.py)
- **Purpose:** Define structured data for M365 identity, session, region configuration, and credentials.
- **Key M365 Models:**
    - `M365IdentityInfo`: Holds M365 identity metadata, including tenant ID, domain(s), user, and location.
    - `M365RegionConfig`: Stores the specific region/authority and API base URL for the tenant.
    - `M365Credentials`: Represents credentials for authentication (user, password, client ID, client secret, tenant ID, etc.).

### `M365Service` (Service Base Class)

- **Location:** [`prowler/providers/m365/lib/service/service.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/lib/service/service.py)
- **Purpose:** Abstract base class for all M365 service-specific classes.
- **Key M365 Responsibilities:**
    - Receives an `M365Provider` instance to access session, identity, and configuration.
    - Manages the Microsoft Graph API client for the service.
    - Initializes a PowerShell client for most services if credentials and identity are available.
    - Exposes common audit context (`audit_config`, `fixer_config`) to subclasses.

### Exception Handling

- **Location:** [`prowler/providers/m365/exceptions/exceptions.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/exceptions/exceptions.py)
- **Purpose:** Custom exception classes for M365-specific error handling, such as credential, session, region, and argument errors.

### Session and Utility Helpers

- **Location:** [`prowler/providers/m365/lib/`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/lib/)
- **Purpose:** Helpers for argument parsing, region/authority setup, mutelist management, PowerShell integration, and other cross-cutting concerns.

  > **Key File: [`m365_powershell.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/lib/powershell/m365_powershell.py)**
  >
  > This is the core module for Microsoft 365 PowerShell integration. It manages authentication, session handling, and provides a comprehensive set of methods for interacting with Microsoft Teams, Exchange Online, and Defender policies via PowerShell.
  >
  > This module provides secure credential management and authentication using MSAL and PowerShell. It handles automated installation and initialization of required PowerShell modules. The module offers a rich set of methods for retrieving and managing Teams, Exchange, and Defender configurations. It serves as the central component for all M365 provider operations that require PowerShell automation.

## Specific Patterns in M365 Services

The generic service pattern is described in [service page](./services.md#service-structure-and-initialisation). You can find all the currently implemented services in the following locations:

- Directly in the code, in location [`prowler/providers/m365/services/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/m365/services)
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new service is by following the [service implementation documentation](./services.md#adding-a-new-service) and by taking other already implemented services as reference.

### M365 Service Common Patterns

- Services communicate with Microsoft 365 using the Microsoft Graph API **and/or PowerShell**. See the [official documentation](https://learn.microsoft.com/en-us/graph/api/overview) and [PowerShell reference](https://learn.microsoft.com/en-us/powershell/).
- Every M365 service class inherits from `M365Service`, ensuring access to session, identity, configuration, and client utilities.
- The constructor (`__init__`) always calls `super().__init__` with the provider object, and initializes the Graph client and the PowerShell client.
- Resource containers **must** be initialized in the constructor, typically as objects that represent the different settings of the service.
- All M365 resources are represented as Pydantic `BaseModel` classes, providing type safety and structured access to resource attributes.
- Microsoft Graph API and PowerShell calls are wrapped in try/except blocks, always logging errors.
- To retrieve some data in the services, it is so common that you have to create a new method also in the `m365_powershell.py` file to later be called in the service.

## Specific Patterns in M365 Checks

The M365 checks pattern is described in [checks page](./checks.md). You can find all the currently implemented checks in:

- Directly in the code, within each service folder, each check has its own folder named after the name of the check. (e.g. [`prowler/providers/m365/services/entra/entra_users_mfa_enabled/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/m365/services/entra/entra_users_mfa_enabled))
- In the [Prowler Hub](https://hub.prowler.com/) for a more human-readable view.

The best reference to understand how to implement a new check is following the [M365 check implementation documentation](./checks.md#creating-a-check) and by taking other checks as reference.

### Check Report Class

The `CheckReportM365` class models a single finding for a Microsoft 365 resource in a check report. It is defined in [`prowler/lib/check/models.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/check/models.py) and inherits from the generic `Check_Report` base class.

#### Purpose

`CheckReportM365` extends the base report structure with M365-specific fields, enabling detailed tracking of the resource, name, and location associated with each finding.

#### Constructor and Attribute Population

When you instantiate `CheckReportM365`, you must provide the check metadata and a resource object. The class will attempt to automatically populate its M365-specific attributes from the resource, using the following logic (in order of precedence):

- **`resource_id`**: A required field that **must** be explicitly set in the constructor to identify the resource being checked.
- **`resource_name`**: A required field that **must** be explicitly set in the constructor to provide a human-readable name for the resource.
- **`location`**: A required field that can be explicitly set in the constructor to indicate where the resource is located. If not specified, defaults to "global".

If the resource object does not contain the required attributes, you must set them manually in the check logic.

Other attributes are inherited from the `Check_Report` class, from which you **always** have to set the `status` and `status_extended` attributes in the check logic.

#### Example Usage

```python
report = CheckReportM365(
    metadata=check_metadata,
    resource=resource_object
)
report.status = "PASS"
report.status_extended = "Resource is compliant."
```
