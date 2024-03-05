from abc import ABC, abstractmethod

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


class Provider(ABC):

    @property
    @abstractmethod
    def type(self):
        """
        type method stores the provider's type.

        This method needs to be created in each provider.
        """

    @property
    @abstractmethod
    def identity(self):
        """
        identity method stores the provider's identity to audit.

        This method needs to be created in each provider.
        """

    @property
    @abstractmethod
    def session(self):
        """
        session method stores the provider's session to audit.

        This method needs to be created in each provider.
        """

    @property
    @abstractmethod
    def audit_config(self):
        """
        audit_config method stores the provider's audit configuration.

        This method needs to be created in each provider.
        """

    @abstractmethod
    def print_credentials(self):
        """
        print_credentials is used to display in the CLI the provider's credentials used to audit.

        This method needs to be created in each provider.
        """

    @abstractmethod
    def setup_session(self):
        pass

    @property
    @abstractmethod
    def output_options(self):
        """
        output_options method returns the provider's audit output configuration.

        This method needs to be created in each provider.
        """

    @output_options.setter
    @abstractmethod
    def output_options(self):
        """
        output_options.setter sets the provider's audit output configuration.

        This method needs to be created in each provider.
        """

    # TODO: probably this won't be here since we want to do the arguments validation during the parse()
    def validate_arguments(self):
        pass

    def get_checks_to_execute_by_audit_resources(self):
        """
        get_checks_to_execute_by_audit_resources returns a set of checks based on the input resources to scan.

        This is a fallback that returns None if the service has not implemented this function.
        """
