import os
from os import environ

from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.mongodbatlas.exceptions.exceptions import (
    MongoDBAtlasAuthenticationError,
    MongoDBAtlasCredentialsError,
    MongoDBAtlasIdentityError,
    MongoDBAtlasSessionError,
)
from prowler.providers.mongodbatlas.lib.mutelist.mutelist import MongoDBAtlasMutelist
from prowler.providers.mongodbatlas.models import (
    MongoDBAtlasIdentityInfo,
    MongoDBAtlasSession,
)


class MongodbatlasProvider(Provider):
    """
    MongoDB Atlas Provider class

    This class is responsible for setting up the MongoDB Atlas provider,
    including the session, identity, audit configuration, and mutelist.
    """

    _type: str = "mongodbatlas"
    _session: MongoDBAtlasSession
    _identity: MongoDBAtlasIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        atlas_public_key: str = "",
        atlas_private_key: str = "",
        # Provider configuration
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        # Optional filters
        atlas_project_id: str = None,
    ):
        """
        MongoDB Atlas Provider constructor

        Args:
            atlas_public_key: MongoDB Atlas API public key
            atlas_private_key: MongoDB Atlas API private key
            config_path: Path to the audit configuration file
            config_content: Audit configuration content
            fixer_config: Fixer configuration content
            mutelist_path: Path to the mutelist file
            mutelist_content: Mutelist content
            atlas_project_id: Project ID to filter
        """
        logger.info("Instantiating MongoDB Atlas Provider...")

        self._session = MongodbatlasProvider.setup_session(
            atlas_public_key,
            atlas_private_key,
        )

        self._identity = MongodbatlasProvider.setup_identity(self._session)

        # Store filter options
        self._project_id = atlas_project_id

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = MongoDBAtlasMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = MongoDBAtlasMutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

    @property
    def type(self):
        """Returns the type of the MongoDB Atlas provider"""
        return self._type

    @property
    def session(self):
        """Returns the session object for the MongoDB Atlas provider"""
        return self._session

    @property
    def identity(self):
        """Returns the identity information for the MongoDB Atlas provider"""
        return self._identity

    @property
    def audit_config(self):
        """Returns the audit configuration for the MongoDB Atlas provider"""
        return self._audit_config

    @property
    def fixer_config(self):
        """Returns the fixer configuration for the MongoDB Atlas provider"""
        return self._fixer_config

    @property
    def mutelist(self) -> MongoDBAtlasMutelist:
        """Returns the mutelist for the MongoDB Atlas provider"""
        return self._mutelist

    @property
    def project_id(self):
        """Returns the project ID filter"""
        return self._project_id

    @staticmethod
    def setup_session(
        atlas_public_key: str = None,
        atlas_private_key: str = None,
    ) -> MongoDBAtlasSession:
        """
        Setup MongoDB Atlas session with authentication credentials

        Args:
            atlas_public_key: MongoDB Atlas API public key
            atlas_private_key: MongoDB Atlas API private key

        Returns:
            MongoDBAtlasSession: Authenticated session for API requests

        Raises:
            MongoDBAtlasCredentialsError: If credentials are missing
            MongoDBAtlasSessionError: If session setup fails
        """
        try:
            public_key = atlas_public_key
            private_key = atlas_private_key

            # Check environment variables if not provided
            if not public_key:
                public_key = environ.get("ATLAS_PUBLIC_KEY", "")
            if not private_key:
                private_key = environ.get("ATLAS_PRIVATE_KEY", "")

            if not public_key or not private_key:
                raise MongoDBAtlasCredentialsError(
                    file=os.path.basename(__file__),
                    message="MongoDB Atlas API credentials not found. Please provide --atlas-public-key and --atlas-private-key or set ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY environment variables.",
                )

            session = MongoDBAtlasSession(
                public_key=public_key,
                private_key=private_key,
            )

            return session

        except MongoDBAtlasCredentialsError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise MongoDBAtlasSessionError(
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: MongoDBAtlasSession) -> MongoDBAtlasIdentityInfo:
        """
        Setup MongoDB Atlas identity information

        Args:
            session: MongoDB Atlas session

        Returns:
            MongoDBAtlasIdentityInfo: Identity information

        Raises:
            MongoDBAtlasAuthenticationError: If authentication fails
            MongoDBAtlasIdentityError: If identity setup fails
        """
        try:
            import requests
            from requests.auth import HTTPDigestAuth

            # Test authentication by getting organizations
            auth = HTTPDigestAuth(session.public_key, session.private_key)
            headers = {
                "Accept": "application/vnd.atlas.2023-01-01+json",
                "Content-Type": "application/json",
            }

            response = requests.get(
                f"{session.base_url}/orgs",
                auth=auth,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 401:
                raise MongoDBAtlasAuthenticationError(
                    file=os.path.basename(__file__),
                    message="MongoDB Atlas authentication failed. Please check your API credentials.",
                )

            response.raise_for_status()
            organizations_data = response.json()

            # Extract organization information from the response
            if (
                organizations_data
                and "results" in organizations_data
                and len(organizations_data["results"]) > 0
            ):
                org = organizations_data["results"][0]
                org_id = org.get("id", "")
                org_name = org.get("name", "Unknown Organization")

                identity = MongoDBAtlasIdentityInfo(
                    organization_id=org_id,  # Use organization ID as user_id
                    organization_name=org_name,  # Use organization name as username
                    roles=[
                        "ORGANIZATION_ADMIN"
                    ],  # Indicate this is an organization-level access
                )
            else:
                # Use public key as identifier and create a username from public key if no organizations found
                identity = MongoDBAtlasIdentityInfo(
                    organization_id=session.public_key,  # Use public key as identifier
                    organization_name=f"api-key-{session.public_key[:8]}",  # Create a username from public key
                    roles=["API_KEY"],  # Indicate this is an API key authentication
                )

            return identity

        except MongoDBAtlasAuthenticationError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise MongoDBAtlasIdentityError(
                original_exception=error,
            )

    def print_credentials(self):
        """Print the MongoDB Atlas credentials"""
        report_lines = [
            f"MongoDB Atlas Organization ID: {Fore.YELLOW}{self.identity.organization_id}{Style.RESET_ALL}",
        ]

        if self.project_id:
            report_lines.append(
                f"Project ID Filter: {Fore.YELLOW}{self.project_id}{Style.RESET_ALL}"
            )

        report_title = (
            f"{Style.BRIGHT}Using the MongoDB Atlas credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        atlas_public_key: str = "",
        atlas_private_key: str = "",
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test connection to MongoDB Atlas

        Args:
            atlas_public_key: MongoDB Atlas API public key
            atlas_private_key: MongoDB Atlas API private key
            raise_on_exception: Whether to raise exceptions

        Returns:
            Connection: Connection status
        """
        try:
            session = MongodbatlasProvider.setup_session(
                atlas_public_key=atlas_public_key,
                atlas_private_key=atlas_private_key,
            )

            MongodbatlasProvider.setup_identity(session)

            return Connection(is_connected=True)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
