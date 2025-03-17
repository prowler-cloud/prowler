# Library imports to authenticate in the Provider

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import parse_mutelist_file
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.opennebula.models import (
    # All providers models needed
    ProviderSessionModel,
    ProviderIdentityModel,
    ProviderOutputOptionsModel
)

class OpenNebulaProvider(Provider):
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