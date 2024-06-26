import importlib
import pkgutil
import sys
from abc import ABC, abstractmethod
from importlib import import_module
from typing import Any, Optional

from prowler.config.config import get_default_mute_file_path
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import (
    get_mutelist_file_from_local_file,
    validate_mutelist,
)

providers_path = "prowler.providers"


# TODO: with this we can enforce that all classes ending with "Provider" needs to inherint from the Provider class
# class ProviderMeta:
#     def __init__(cls, name, bases, dct):
#         # Check if the class name ends with 'Provider'
#         if name.endswith("Provider"):
#             # Check if any base class is a subclass of Provider (or is Provider itself)
#             if not any(issubclass(b, Provider) for b in bases if b is not object):
#                 raise TypeError(f"{name} must inherit from Provider")
#         super().__init__(name, bases, dct)
# class Provider(metaclass=ProviderMeta):


# TODO: enforce audit_metadata for all the providers
class Provider(ABC):
    _global: Optional["Provider"] = None
    _mutelist: dict
    _mutelist_file_path: str
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
        get_output_mapping(): Returns the output mapping between the provider and the generic model.
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

    @abstractmethod
    def get_output_mapping(self) -> dict:
        """
        get_output_mapping returns the output mapping between the provider and the generic model.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    # TODO: probably this won't be here since we want to do the arguments validation during the parse()
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
    def mutelist(self):
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    @property
    def mutelist_file_path(self):
        """
        mutelist method returns the provider's mutelist file path.
        """
        return self._mutelist_file_path

    @mutelist.setter
    def mutelist(self, mutelist_path):
        """
        mutelist.setter sets the provider's mutelist.
        """
        # Set default mutelist path if none is set
        if not mutelist_path:
            mutelist_path = get_default_mute_file_path(self.type)
        if mutelist_path:
            mutelist = get_mutelist_file_from_local_file(mutelist_path)
            mutelist = validate_mutelist(mutelist)
        else:
            mutelist = {}

        self._mutelist = mutelist
        self._mutelist_file_path = mutelist_path

    @staticmethod
    def get_global_provider() -> "Provider":
        return Provider._global

    @staticmethod
    def set_global_provider(arguments):
        try:
            provider_class_path = (
                f"{providers_path}.{arguments.provider}.{arguments.provider}_provider"
            )
            provider_class_name = f"{arguments.provider.capitalize()}Provider"
            provider_class = getattr(
                import_module(provider_class_path), provider_class_name
            )
            if not isinstance(Provider._global, provider_class):
                global_provider = provider_class(arguments)

            Provider._global = global_provider
        except TypeError as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    @staticmethod
    def get_available_providers() -> list[str]:
        """get_available_providers returns a list of the available providers"""
        providers = []
        # Dynamically import the package based on its string path
        prowler_providers = importlib.import_module(providers_path)
        # Iterate over all modules found in the prowler_providers package
        for _, provider, ispkg in pkgutil.iter_modules(prowler_providers.__path__):
            if provider != "common" and ispkg:
                providers.append(provider)
        return providers

    @staticmethod
    def update_provider_config(audit_config: dict, variable: str, value: str):
        try:
            if audit_config and variable in audit_config:
                audit_config[variable] = value

            return audit_config
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
