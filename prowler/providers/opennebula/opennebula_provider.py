import pyone  
from configparser import ConfigParser
from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.opennebula.models import (
    OpenNebulaSession,
    OpenNebulaIdentity,
    OpenNebulaOutputOptions
)
from prowler.providers.opennebula.exceptions.exceptions import OpenNebulaError
from colorama import Fore

class OpenNebulaProvider(Provider):
    _type: str = "opennebula"
    _identity: OpenNebulaIdentity
    _session: OpenNebulaSession
    _audit_config: dict
    _output_options: OpenNebulaOutputOptions
    _mutelist: dict
    audit_metadata: Audit_Metadata

    def __init__(
        self, 
        credentials_file: str = None,
        config_file: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = {},
    ):
        """
        Initializes the OpenNebulaProvider instance.
        Args:
            arguments (dict): A dictionary containing configuration arguments.
        """
        logger.info("Setting OpenNebula provider...")
        
        # Set up the session
        self._session = self.setup_session(credentials_file)
        
        # Set the identity
        self._identity = self.set_identity()
        
        # Set the output options
        self._output_options = OpenNebulaOutputOptions(
            None,
            {},
            self.identity
        )
        
        # Set provider configuration
        self._audit_config = load_and_validate_config_file(
            config_file,
        )

        # Mutelist
        if mutelist_content:
            self._mutelist = mutelist_content
        else:
            if not mutelist_path:
                mutelist_path = {}
            self._mutelist = mutelist_path

        # Set audit metadata
        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            credentials_file=credentials_file,
        )

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

    @staticmethod
    def setup_session(
        self, 
        credentials_file: str = None
    ) -> OpenNebulaSession:
        """
        Sets up the OpenNebula session.
        
        Args:
            credentials_file (str): Path to the credentials file.
            
        Returns:
            OpenNebulaSessionModel: Session credentials for OpenNebula.
        """
        config = ConfigParser()
        config.read(credentials_file)
        
        endpoint = config.get('opennebula', 'endpoint')
        username = config.get('opennebula', 'username')
        auth_token = config.get('opennebula', 'auth_token')
        
        # Create OpenNebula client
        client = pyone.OneServer(endpoint, f"{username}:{auth_token}")
        self.test_connection(client)
        return OpenNebulaSession(
            client=client,
            endpoint=endpoint,
            username=username,
            auth_token=auth_token
        )

    def print_credentials(self):
        """Print the provider's credentials information."""
        print_boxes(
            [
                f"OpenNebula User: {Fore.YELLOW}{self.identity.user_name}{Fore.RESET}",
            ]
        )

    def test_connection(client: pyone.OneServer):
        """Test the connection to the OpenNebula API."""
        try:
            client.system.version()
            logger.info("Connection to OpenNebula API successful.")
        except Exception as e:
            logger.error("Connection to OpenNebula API failed.")
            raise OpenNebulaError(original_exception=e)
    
    def set_identity(self) -> OpenNebulaIdentity:
        """Set the identity of the OpenNebula provider."""
        identity = self._session.client.user.info(-1),
        user_id = identity.get('ID')
        user_name = identity.get('NAME')
        group_id = identity.get('GID')
        group_name = identity.get('GNAME')
        return OpenNebulaIdentity(
            user_id=user_id,
            user_name=user_name,
            group_id=group_id,
            group_name=group_name
        ) 