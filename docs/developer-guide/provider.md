# Prowler Providers

## Introduction

Providers form the backbone of Prowler, enabling security assessments across various cloud environments.

A provider is any platform or service that offers resources, data, or functionality that can be audited for security and compliance. This includes:

- Cloud Infrastructure Providers (like Amazon Web Services, Microsoft Azure, and Google Cloud)
- Software as a Service (SaaS) Platforms (like Microsoft 365)
- Development Platforms (like GitHub)
- Container Orchestration Platforms (like Kubernetes)

For providers supported by Prowler, refer to [Prowler Hub](https://hub.prowler.com/).

???+ important
    There are some custom providers added by the community, like [NHN Cloud](https://www.nhncloud.com/), that are not maintained by the Prowler team, but can be used in the Prowler CLI. They can be checked directly at the [Prowler GitHub repository](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

## Adding a New Provider

To integrate an unsupported Prowler provider and implement its security checks, create a dedicated folder for all related files (e.g., services, checks)."

This folder must be placed within [`prowler/providers/<new_provider_name>/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

Within this folder the following folders are also to be created:

- `lib` – Stores additional utility functions and core files required by every provider. The following files and subfolders are commonly found in every provider's `lib` folder:

    - `service/service.py` – Provides a generic service class to be inherited by all services.
    - `arguments/arguments.py` – Handles provider-specific argument parsing.
    - `mutelist/mutelist.py` – Manages the mutelist functionality for the provider.

- `services` – Stores all [services](./services.md) that the provider offers and want to be audited by [Prowler checks](./checks.md).

- `__init__.py` (empty) – Ensures Python recognizes this folder as a package.

- `<new_provider_name>_provider.py` – Defines authentication logic, configurations, and other provider-specific data.

- `models.py` – Contains necessary models for the new provider.

By adhering to this structure, Prowler can effectively support services and security checks for additional providers.

???+ important
    If your new provider requires a Python library (such as an official SDK or API client) to connect to its services, make sure to add it as a dependency in the `pyproject.toml` file. This ensures that all contributors and users have the necessary packages installed when working with your provider.

## Provider Structure in Prowler

Prowler's provider architecture is designed to facilitate security audits through a generic service tailored to each provider. This is accomplished by passing the necessary parameters to the constructor, which initializes all required session values.

### Base Class

All Prowler providers inherit from the same base class located in [`prowler/providers/common/provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py). It is an [abstract base class](https://docs.python.org/3/library/abc.html) that defines the interface for all provider classes.

### Provider Class

#### Provider Implementation Guidance

Given the complexity and variability of providers, use existing provider implementations as templates when developing new integrations.

- [AWS](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- [GCP](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- [Azure](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- [Kubernetes](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)
- [Microsoft365](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/microsoft365/microsoft365_provider.py)
- [GitHub](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/github_provider.py)

### Basic Provider Implementation: Pseudocode Example

To simplify understanding, the following pseudocode outlines the fundamental structure of a provider, including library imports necessary for authentication.

```python title="Provider Example Class"

# Library Imports for Authentication

# When implementing authentication for a provider, import the required libraries.

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import parse_mutelist_file
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.<new_provider_name>.models import (
    # All provider models needed.
    ProviderSessionModel,
    ProviderIdentityModel,
    ProviderOutputOptionsModel
)

class NewProvider(Provider):
    # All properties from the class, some of which are properties in the base class.
    _type: str = "<provider_name>"
    _session: <ProviderSessionModel>
    _identity: <ProviderIdentityModel>
    _audit_config: dict
    _output_options: ProviderOutputOptionsModel
    _mutelist: dict
    audit_metadata: Audit_Metadata

    def __init__(self, arguments):
        """
        Initializes the NewProvider instance.
        Args:
            arguments (dict): A dictionary containing configuration arguments.
        """
        logger.info("Setting <NewProviderName> provider ...")

        # Initializing the Provider Session

        # Steps:

        # - Retrieve Account Information
        # - Extract relevant account identifiers (subscriptions, projects, or other service references) from the provided arguments.

        # Establish a Session

        # Use the method enforced by the parent class to set up the session:
        self._session = self.setup_session(credentials_file)

        # Define Provider Identity
        # Assign the identity class, typically provided by the Python provider library:
        self._identity = <ProviderIdentityModel>()

        # Configure the Provider
        # Set the provider-specific configuration.
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
        )

    # All the enforced properties by the parent class.
    @property
    def identity(self):
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def type(self):
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def output_options(self):
        return self._output_options

    def setup_session(self, <all_needed_for_auth>):
        """
        Sets up the Provider session.

        Args:
            <all_needed_for_auth> Can include all necessary arguments to set up the session

        Returns:
            Credentials necessary to communicate with the provider.
        """
        pass

    """
    This method is enforced by parent class and is used to print all relevant
    information during the prowler execution as a header of execution.
    Displaying Account Information with Color Formatting. In Prowler, Account IDs, usernames, and other identifiers are typically displayed using color formatting provided by the colorama module (Fore).
    """
    def print_credentials(self):
        pass
```
