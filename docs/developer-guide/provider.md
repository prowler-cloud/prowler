
# Create a new Provider for Prowler

Here you can find how to create a new Provider in Prowler to give support for making all security checks needed and make your cloud safer!

## Introduction

Providers are the foundation on which Prowler is built, a simple definition for a cloud provider could be "third-party company that offers a platform where any IT resource you need is available at any time upon request". The most well-known cloud providers are Amazon Web Services, Azure from Microsoft and Google Cloud which are already supported by Prowler.

To create a new provider that is not supported now by Prowler and add your security checks you must create a new folder to store all the related files within it (services, checks, etc.). It must be store in route `prowler/providers/<new_provider_name>/`.

Inside that folder, you MUST create the following files and folders:

- A `lib` folder: to store all extra functions.
- A `services` folder: to store all [services](./services.md) to audit.
- An empty `__init__.py`: to make Python treat this service folder as a package.
- A `<new_provider_name>_provider.py`, containing all the provider's logic necessary to get authenticated in the provider, configurations and extra data useful for final report.
- A `models.py`, containing all the models necessary for the new provider.

## Provider

The structure for Prowler's providers is set up in such a way that they can be utilized through a generic service specific to each provider. This is achieved by passing the required parameters to the constructor, which in turn initializes all the necessary session values.

### Base Class

All the providers in Prowler inherits from the same [base class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py). It is an [abstract base class](https://docs.python.org/3/library/abc.html) that defines the interface for all provider classes. The code of the class is the next:

```python title="Provider Base Class"

from abc import ABC, abstractmethod
from typing import Any

class Provider(ABC):
    """
    The Provider class is an abstract base class that defines the interface for all provider classes in the auditing system.

    Attributes:
        type (property): The type of the provider.
        identity (property): The identity of the provider for auditing.
        session (property): The session of the provider for auditing.
        audit_config (property): The audit configuration of the provider.
        output_options (property): The output configuration of the provider for auditing.

    Methods:
        print_credentials(): Displays the provider's credentials used for auditing in the command-line interface.
        setup_session(): Sets up the session for the provider.
        validate_arguments(): Validates the arguments for the provider.
        get_checks_to_execute_by_audit_resources(): Returns a set of checks based on the input resources to scan.

    Note:
        This is an abstract base class and should not be instantiated directly. Each provider should implement its own
        version of the Provider class by inheriting from this base class and implementing the required methods and properties.
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
        get_checks_to_execute_by_audit_resources returns a set of checks based on the input resources to scan.

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

Due to the complexity and differences of each provider use the rest of the providers as a template for the implementation.

- [AWS](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- [GCP](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- [Azure](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- [Kubernetes](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)

To facilitate understanding here is a pseudocode of how the most basic provider could be with examples.

```python title="Provider Example Class"

# Library imports to authenticate in the Provider

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import parse_mutelist_file
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.<new_provider_name>.models import (
    # All providers models needed
    ProviderSessionModel,
    ProviderIdentityModel,
    ProviderOutputOptionsModel
)

class NewProvider(Provider):
    # All properties from the class, some of this are properties in the base class
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
        # First get from arguments the necessary from the cloud account (subscriptions or projects or whatever the provider use for storing services)

        # Set the session with the method enforced by parent class
        self._session = self.setup_session(credentials_file)

        # Set the Identity class normaly the provider class give by Python provider library
        self._identity = <ProviderIdentityModel>()

        # Set the provider configuration
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
        )

    # All enforced properties by the parent class
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
            <all_needed_for_auth> Can include all necessary arguments to setup the session

        Returns:
            Credentials necessary to communicate with the provider.
        """
        pass

    """
    This method is enforced by parent class and is used to print all relevant
    information during the prowler execution as a header of execution.
    Normally the Account ID, User name or stuff like this is displayed in colors using the colorama module (Fore).
    """
    def print_credentials(self):
        pass



```
