import os

from colorama import Fore, Style
from scaleway import Client
from scaleway.iam.v1alpha1 import IamV1Alpha1API

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.scaleway.exceptions.exceptions import (
    ScalewayAuthenticationError,
    ScalewayCredentialsError,
    ScalewayIdentityError,
    ScalewaySessionError,
)
from prowler.providers.scaleway.lib.mutelist.mutelist import ScalewayMutelist
from prowler.providers.scaleway.models import (
    ScalewayIdentityInfo,
    ScalewaySession,
)


class ScalewayProvider(Provider):
    """Scaleway provider.

    Authenticates against the Scaleway API using an API key (access key +
    secret key) and exposes a single global session that every service
    reuses. Scaleway scopes everything to an organization, so the
    organization ID is the audit identity.
    """

    _type: str = "scaleway"
    _session: ScalewaySession
    _identity: ScalewayIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: ScalewayMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        access_key: str = None,
        secret_key: str = None,
        organization_id: str = None,
        project_id: str = None,
        region: str = None,
        # Provider configuration
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating Scaleway provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = ScalewayProvider.setup_session(
            access_key=access_key,
            secret_key=secret_key,
            organization_id=organization_id,
            project_id=project_id,
            region=region,
        )

        self._identity = ScalewayProvider.setup_identity(self._session)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = ScalewayMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = ScalewayMutelist(mutelist_path=mutelist_path)

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
    def mutelist(self) -> ScalewayMutelist:
        return self._mutelist

    @staticmethod
    def setup_session(
        access_key: str = None,
        secret_key: str = None,
        organization_id: str = None,
        project_id: str = None,
        region: str = None,
    ) -> ScalewaySession:
        """Initialize the Scaleway API session.

        Credentials can be provided as arguments (for API/SDK use) or read
        from the official Scaleway environment variables:

        - ``SCW_ACCESS_KEY``
        - ``SCW_SECRET_KEY``
        - ``SCW_DEFAULT_ORGANIZATION_ID``
        - ``SCW_DEFAULT_PROJECT_ID``
        - ``SCW_DEFAULT_REGION``

        Args:
            access_key: Scaleway API access key.
            secret_key: Scaleway API secret key.
            organization_id: Default organization ID to scope the audit.
            project_id: Default project ID for project-scoped resources.
            region: Default region.

        Returns:
            ScalewaySession: The initialized session, holding the
            authenticated ``scaleway.Client``.

        Raises:
            ScalewayCredentialsError: Access or secret key missing.
            ScalewaySessionError: Client instantiation failed.
        """
        access = access_key or os.environ.get("SCW_ACCESS_KEY", "")
        secret = secret_key or os.environ.get("SCW_SECRET_KEY", "")
        org = organization_id or os.environ.get("SCW_DEFAULT_ORGANIZATION_ID") or None
        project = project_id or os.environ.get("SCW_DEFAULT_PROJECT_ID") or None
        default_region = region or os.environ.get("SCW_DEFAULT_REGION") or "fr-par"

        if not access or not secret:
            raise ScalewayCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "Scaleway credentials not found. Provide access_key and "
                    "secret_key or set the SCW_ACCESS_KEY and SCW_SECRET_KEY "
                    "environment variables."
                ),
            )

        try:
            client = Client(
                access_key=access,
                secret_key=secret,
                default_organization_id=org,
                default_project_id=project,
                default_region=default_region,
            )
            return ScalewaySession(
                access_key=access,
                secret_key=secret,
                organization_id=org,
                default_project_id=project,
                default_region=default_region,
                client=client,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise ScalewaySessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: ScalewaySession) -> ScalewayIdentityInfo:
        """Resolve the audit identity by calling Scaleway IAM.

        Uses ``iam.get_api_key`` on the current access key to discover the
        bearer (user vs application). When the bearer is a user, the
        owning organization is read from the user record; otherwise we
        require ``SCW_DEFAULT_ORGANIZATION_ID``.
        """
        try:
            iam = IamV1Alpha1API(session.client)
            current_key = iam.get_api_key(access_key=session.access_key)

            bearer_id = current_key.user_id or current_key.application_id
            bearer_type = (
                "user"
                if current_key.user_id
                else ("application" if current_key.application_id else None)
            )

            organization_id = session.organization_id
            bearer_email = None
            account_root_user_id = None

            # If the bearer is a user, resolve the org from the user record
            # and surface the email + root user id for the credentials banner.
            if current_key.user_id:
                user = iam.get_user(user_id=current_key.user_id)
                organization_id = organization_id or user.organization_id
                bearer_email = user.email
                account_root_user_id = user.account_root_user_id
            elif current_key.application_id and not organization_id:
                # Application keys do not expose the org directly without an
                # extra call. The default org from env is preferred.
                logger.warning(
                    "Scaleway application-scoped API key without "
                    "SCW_DEFAULT_ORGANIZATION_ID. Resource discovery may fail."
                )
            # NOTE: application-scoped keys never resolve account_root_user_id
            # here (the IAM API does not expose it for an application bearer).
            # The IAM service falls back to the org's user list to recover it;
            # if that is unavailable, iam_api_keys_no_root_owned degrades to
            # MANUAL rather than silently PASSing root-owned keys.

            if not organization_id:
                raise ScalewayIdentityError(
                    file=os.path.basename(__file__),
                    message=(
                        "Could not determine the Scaleway organization ID. "
                        "Set SCW_DEFAULT_ORGANIZATION_ID or use a user-scoped "
                        "API key."
                    ),
                )

            return ScalewayIdentityInfo(
                organization_id=organization_id,
                bearer_id=bearer_id,
                bearer_type=bearer_type,
                bearer_email=bearer_email,
                account_root_user_id=account_root_user_id,
            )
        except ScalewayIdentityError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise ScalewayIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def validate_credentials(session: ScalewaySession) -> None:
        """Smoke-test credentials by resolving the current API key.

        Uses ``iam.get_api_key`` because it does not require any prior
        knowledge of the bearer or the owning organization.

        Args:
            session: The Scaleway session to validate.

        Raises:
            ScalewayAuthenticationError: Authentication or authorization
                failed against the Scaleway IAM API.
        """
        try:
            iam = IamV1Alpha1API(session.client)
            iam.get_api_key(access_key=session.access_key)
        except Exception as error:
            raise ScalewayAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Scaleway credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Authentication: {Fore.YELLOW}API Key{Style.RESET_ALL}",
            f"Access Key: {Fore.YELLOW}{self._session.access_key}{Style.RESET_ALL}",
            f"Organization ID: {Fore.YELLOW}{self._identity.organization_id}{Style.RESET_ALL}",
        ]
        if self._identity.bearer_type:
            report_lines.append(
                f"Bearer: {Fore.YELLOW}{self._identity.bearer_type}"
                f" ({self._identity.bearer_email or self._identity.bearer_id})"
                f"{Style.RESET_ALL}"
            )
        if self._session.default_region:
            report_lines.append(
                f"Default Region: {Fore.YELLOW}{self._session.default_region}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        access_key: str = None,
        secret_key: str = None,
        organization_id: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test connection to Scaleway.

        Args:
            access_key: Scaleway access key (falls back to SCW_ACCESS_KEY).
            secret_key: Scaleway secret key (falls back to SCW_SECRET_KEY).
            organization_id: Organization ID to scope the audit.
            raise_on_exception: Whether to raise or return errors.
            provider_id: Expected Scaleway organization ID. When provided,
                the resolved identity must match it; otherwise the test
                fails with ``ScalewayAuthenticationError``.

        Returns:
            Connection: Connection object with is_connected status.
        """
        try:
            session = ScalewayProvider.setup_session(
                access_key=access_key,
                secret_key=secret_key,
                organization_id=organization_id,
            )
            ScalewayProvider.validate_credentials(session)

            # Guard for API callers that already know the expected
            # organization: the credentials must point to that exact org.
            if provider_id:
                identity = ScalewayProvider.setup_identity(session)
                if identity.organization_id != provider_id:
                    raise ScalewayAuthenticationError(
                        file=os.path.basename(__file__),
                        message=(
                            "The provided credentials do not have access to "
                            f"the Scaleway organization with ID: {provider_id}"
                        ),
                    )

            return Connection(is_connected=True)

        except (
            ScalewayCredentialsError,
            ScalewaySessionError,
            ScalewayAuthenticationError,
            ScalewayIdentityError,
        ) as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(is_connected=False, error=error)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            formatted_error = ScalewayAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )
            if raise_on_exception:
                raise formatted_error
            return Connection(is_connected=False, error=formatted_error)

    def validate_arguments(self) -> None:
        return None
