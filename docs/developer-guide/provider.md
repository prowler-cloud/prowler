# Creating a New Provider in Prowler

Below are instructions for creating new providers in Prowler with all the relevant checks in order to achieve a safer cloud.

## Introduction

Providers form the backbone of Prowler, enabling security assessments across various cloud environments. 

A cloud provider is a third-party company that offers on-demand IT resources via its platform. Prowler currently supports the most widely used cloud providers, including:  
  
Amazon Web Services (AWS)  
  
Microsoft Azure  
  
Google Cloud Platform (GCP)

Adding a New Provider  

To integrate a cloud provider not yet supported by Prowler and implement security checks, follow these steps: Create a dedicated folder to store all related files (services, checks, etc.).  
  
This folder must be placed within `prowler/providers/<new_provider_name>/`.

Within this folder the following folders are also to be created:

- `lib` – Stores additional utility functions.
- `services` – Stores all [services](./services.md) to audit.
- `__init__.py` (empty) – Ensures Python recognizes this folder as a package.
- `<new_provider_name>_provider.py` – Defines authentication logic, configurations, and other provider-specific data.
- `models.py` – Contains necessary models for the new provider.  
By adhering to this structure, Prowler can effectively support security checks for additional cloud providers.

## Provider Structure in Prowler

Prowler's provider architecture is designed to facilitate security audits through a generic service tailored to each provider. This is accomplished by passing the necessary parameters to the constructor, which initializes all required session values.

### Base Class

All Prowler providers inherit from the same [base class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py). It is an [abstract base class](https://docs.python.org/3/library/abc.html) that defines the interface for all provider classes. 

Class Definition:

```python title="Provider Base Class"

from abc import ABC, abstractmethod
from typing import Any

class Provider(ABC):
    """
    The Provider class is an abstract base class that defines the interface for all provider classes in the auditing system.

    Attributes
        type (property): Specifies the type of provider.
        identity (property): Represents the provider's identity for auditing purposes.
        session (property): Manages the provider's session for audit operations.
        audit_config (property): Stores audit configuration details.
        output_options (property): Defines output settings for auditing.

    Methods
        print_credentials(): Displays the provider's credentials in the CLI.
        setup_session(): Sets up the session for the provider.
        validate_arguments(): Verifies input arguments for validity.
        get_checks_to_execute_by_audit_resources(): Retrieves a set of checks based on the input resources.

    Note:
        This is an abstract base class and **should not be instantiated directly**. Each provider must implement its own version of the `Provider`
        class by inheriting from this base class and defining the necessary methods and attributes.
    """

    @property
    @abstractmethod
    def type(self) -> str:
        """
        type method stores the provider's type.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def identity(self) -> str:
        """
        identity method stores the provider's identity to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @abstractmethod
    def setup_session(self) -> Any:
        """
        setup_session sets up the session for the provider.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def session(self) -> str:
        """
        session method stores the provider's session to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def audit_config(self) -> str:
        """
        audit_config method stores the provider's audit configuration.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @abstractmethod
    def print_credentials(self) -> None:
        """
        print_credentials is used to display in the CLI the provider's credentials used to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def output_options(self) -> str:
        """
        output_options method returns the provider's audit output configuration.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @output_options.setter
    @abstractmethod
    def output_options(self, value: str) -> Any:
        """
        output_options.setter sets the provider's audit output configuration.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    def validate_arguments(self) -> None:
        """
        validate_arguments validates the arguments for the provider.

        This method can be overridden in each provider if needed.
        """
        raise NotImplementedError()

    def get_checks_to_execute_by_audit_resources(self) -> set:
        """
        get_checks_to_execute_by_audit_resources retrieves a set of checks based on the input resources.

        This is a fallback that returns None if the service has not implemented this function.
        """
        return set()

    @property
    @abstractmethod
    def mutelist(self):
        """
        mutelist method returns the provider's mutelist.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @mutelist.setter
    @abstractmethod
    def mutelist(self, path: str):
        """
        mutelist.setter sets the provider's mutelist.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()
```

### Provider Class

Provider Implementation Guidance  

Given the complexity and variability of cloud providers, use existing provider implementations as templates when developing new integrations.

- [AWS](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- [GCP](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- [Azure](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- [Kubernetes](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)
- [Microsoft365](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/microsoft365/microsoft365_provider.py)

Basic Provider Implementation: Pseudocode Example  

To simplify understanding, the following pseudocode outlines the fundamental structure of a provider, including library imports necessary for authentication.

```python title="Provider Example Class"

# Library Imports for Authentication

When implementing authentication for a provider, import the required libraries.

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

# Retrieve Cloud Account Information 
# Extract relevant account identifiers (subscriptions, projects, or other service references) from the provided arguments.

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