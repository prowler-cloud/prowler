import logging
import os

from colorama import Fore, Style
from linode_api4 import LinodeClient

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.linode.exceptions.exceptions import (
    LinodeAuthenticationError,
    LinodeCredentialsError,
    LinodeIdentityError,
    LinodeSessionError,
)
from prowler.providers.linode.lib.mutelist.mutelist import LinodeMutelist
from prowler.providers.linode.models import (
    LinodeIdentityInfo,
    LinodeSession,
)


class LinodeProvider(Provider):
    """Linode provider."""

    _type: str = "linode"
    _session: LinodeSession
    _identity: LinodeIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: LinodeMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        token: str = None,
    ):
        logger.info("Instantiating Linode provider...")

        # Mute noisy HTTP client logs
        logging.getLogger("urllib3").setLevel(logging.WARNING)

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = LinodeProvider.setup_session(token=token)

        self._identity = LinodeProvider.setup_identity(self._session)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = LinodeMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = LinodeMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> LinodeMutelist:
        return self._mutelist

    @staticmethod
    def setup_session(token: str = None) -> LinodeSession:
        """Initialize Linode SDK client.

        Credentials can be provided as argument or read from environment variable:
        - LINODE_TOKEN (Personal Access Token)

        Args:
            token: Linode Personal Access Token (optional, falls back to env var).

        Returns:
            LinodeSession: The initialized Linode session.

        Raises:
            LinodeCredentialsError: If no credentials are provided.
            LinodeSessionError: If session setup fails.
        """
        token = token or os.environ.get("LINODE_TOKEN", "")

        if not token:
            raise LinodeCredentialsError(
                file=os.path.basename(__file__),
                message="Linode credentials not found. Set LINODE_TOKEN environment variable or use --linode-token argument.",
            )

        try:
            client = LinodeClient(token)
            return LinodeSession(client=client, token=token)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise LinodeSessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: LinodeSession) -> LinodeIdentityInfo:
        """Fetch user and account metadata for Linode.

        Args:
            session: The Linode session.

        Returns:
            LinodeIdentityInfo: The identity information.

        Raises:
            LinodeIdentityError: If identity setup fails.
        """
        try:
            client = session.client
            username = None
            email = None
            account_id = None

            try:
                profile = client.profile()
                username = profile.username
                email = profile.email
            except Exception as error:
                logger.warning(
                    f"Unable to retrieve Linode profile info: {error}. Continuing with limited identity details."
                )

            try:
                account = client.account()
                account_id = getattr(account, "euuid", None)
            except Exception as error:
                logger.warning(
                    f"Unable to retrieve Linode account info: {error}. Continuing without account ID."
                )

            return LinodeIdentityInfo(
                username=username,
                email=email,
                account_id=account_id,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise LinodeIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Linode credentials below:{Style.RESET_ALL}"
        )
        report_lines = []

        report_lines.append(
            f"Authentication: {Fore.YELLOW}Personal Access Token{Style.RESET_ALL}"
        )

        if self.identity.username:
            report_lines.append(
                f"Username: {Fore.YELLOW}{self.identity.username}{Style.RESET_ALL}"
            )

        if self.identity.email:
            report_lines.append(
                f"Email: {Fore.YELLOW}{self.identity.email}{Style.RESET_ALL}"
            )

        if self.identity.account_id:
            report_lines.append(
                f"Account ID: {Fore.YELLOW}{self.identity.account_id}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        token: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test connection to Linode.

        Args:
            token: Linode Personal Access Token.
            raise_on_exception: Flag indicating whether to raise an exception if the connection fails.

        Returns:
            Connection: Connection object with is_connected status.
        """
        try:
            session = LinodeProvider.setup_session(token=token)
            # Validate by fetching profile
            session.client.profile()
            return Connection(is_connected=True)
        except LinodeCredentialsError as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise LinodeAuthenticationError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                )
            return Connection(is_connected=False, error=error)
