from abc import ABC, abstractmethod
from typing import Any

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

    # @property
    # @abstractmethod
    # def mutelist(self):
    #     """
    #     mutelist method returns the provider's mutelist.
    #     This method needs to be created in each provider.
    #     """
    #     raise NotImplementedError()

    # @mutelist.setter
    # @abstractmethod
    # def mutelist(self, path: str):
    #     """
    #     mutelist.setter sets the provider's mutelist.
    #     This method needs to be created in each provider.
    #     """
    #     raise NotImplementedError()
