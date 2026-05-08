import asyncio
import os
import re
from os import environ

from colorama import Fore, Style
from okta.client import Client as OktaSDKClient

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
from prowler.providers.okta.exceptions.exceptions import (
    OktaEnvironmentVariableError,
    OktaInvalidCredentialsError,
    OktaInvalidOrgURLError,
    OktaPrivateKeyFileError,
    OktaSetUpIdentityError,
    OktaSetUpSessionError,
)
from prowler.providers.okta.lib.mutelist.mutelist import OktaMutelist
from prowler.providers.okta.models import OktaIdentityInfo, OktaSession

DEFAULT_SCOPES = ["okta.policies.read"]
ORG_URL_RE = re.compile(r"^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$")


class OktaProvider(Provider):
    """Okta Provider class.

    Authenticates against an Okta organization using OAuth 2.0 with a
    private-key JWT (Client Credentials grant). The SDK requests and
    refreshes the access token internally.

    Attributes:
        _type (str): The type of the provider.
        _auth_method (str): The authentication method used by the provider.
        _session (OktaSession): The session object for the provider.
        _identity (OktaIdentityInfo): The identity information for the provider.
        _audit_config (dict): The audit configuration for the provider.
        _fixer_config (dict): The fixer configuration for the provider.
        _mutelist (Mutelist): The mutelist for the provider.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "okta"
    _auth_method: str = None
    _session: OktaSession
    _identity: OktaIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        okta_org_url: str = "",
        okta_client_id: str = "",
        okta_private_key: str = "",
        okta_private_key_file: str = "",
        okta_scopes: str = "",
        okta_kid: str = "",
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """Okta Provider constructor."""
        logger.info("Instantiating Okta Provider...")

        OktaProvider.validate_arguments(
            okta_org_url=okta_org_url,
            okta_client_id=okta_client_id,
            okta_private_key=okta_private_key,
            okta_private_key_file=okta_private_key_file,
        )
        self._session = OktaProvider.setup_session(
            org_url=okta_org_url,
            client_id=okta_client_id,
            private_key=okta_private_key,
            private_key_file=okta_private_key_file,
            scopes=okta_scopes,
            kid=okta_kid,
        )
        self._identity = OktaProvider.setup_identity(self._session)
        self._auth_method = "OAuth 2.0 (private-key JWT)"

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)
        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = OktaMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = OktaMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        return self._auth_method

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def type(self):
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> OktaMutelist:
        return self._mutelist

    @staticmethod
    def validate_arguments(
        okta_org_url: str = "",
        okta_client_id: str = "",
        okta_private_key: str = "",
        okta_private_key_file: str = "",
    ):
        """Validate that all required OAuth credentials are provided.

        Falls back to the matching `OKTA_*` environment variables when a CLI
        argument is not supplied. The private key may be supplied as raw
        content (preferred for API/UI integrations) or as a file path.
        Raises a single combined error if any required value is missing.
        """
        org_url = okta_org_url or environ.get("OKTA_ORG_URL", "")
        client_id = okta_client_id or environ.get("OKTA_CLIENT_ID", "")
        private_key = okta_private_key or environ.get("OKTA_PRIVATE_KEY", "")
        private_key_file = okta_private_key_file or environ.get(
            "OKTA_PRIVATE_KEY_FILE", ""
        )

        missing = []
        if not org_url:
            missing.append("--okta-org-url / OKTA_ORG_URL")
        if not client_id:
            missing.append("--okta-client-id / OKTA_CLIENT_ID")
        if not private_key and not private_key_file:
            missing.append(
                "--okta-private-key / OKTA_PRIVATE_KEY (or "
                "--okta-private-key-file / OKTA_PRIVATE_KEY_FILE)"
            )
        if missing:
            raise OktaEnvironmentVariableError(
                file=os.path.basename(__file__),
                message=(
                    "Okta provider requires all OAuth credentials. Missing: "
                    + ", ".join(missing)
                ),
            )

    @staticmethod
    def setup_session(
        org_url: str = "",
        client_id: str = "",
        private_key: str = "",
        private_key_file: str = "",
        scopes: str = "",
        kid: str = "",
    ) -> OktaSession:
        """Build an OktaSession from CLI args, falling back to environment variables.

        Accepts the private key as raw content (`private_key` /
        `OKTA_PRIVATE_KEY`) or as a file path (`private_key_file` /
        `OKTA_PRIVATE_KEY_FILE`). Content takes precedence when both are
        supplied — this matches the GitHub provider pattern and keeps the
        API/UI integrations from having to write keys to disk.
        """
        try:
            org_url = org_url or environ.get("OKTA_ORG_URL", "")
            client_id = client_id or environ.get("OKTA_CLIENT_ID", "")
            private_key = private_key or environ.get("OKTA_PRIVATE_KEY", "")
            private_key_file = private_key_file or environ.get(
                "OKTA_PRIVATE_KEY_FILE", ""
            )
            scopes = scopes or environ.get("OKTA_SCOPES", "")
            kid = kid or environ.get("OKTA_KID", "")

            org_url = org_url.rstrip("/")
            if not ORG_URL_RE.match(org_url):
                raise OktaInvalidOrgURLError(
                    file=os.path.basename(__file__),
                    message=f"Invalid Okta org URL: '{org_url}'. Expected https://<org>.okta.com (no trailing slash).",
                )

            if private_key:
                private_key = private_key.strip()
            else:
                try:
                    with open(private_key_file, "r") as fh:
                        private_key = fh.read().strip()
                except OSError as error:
                    raise OktaPrivateKeyFileError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                        message=f"Could not read private key file '{private_key_file}': {error}",
                    )
            if not private_key:
                raise OktaPrivateKeyFileError(
                    file=os.path.basename(__file__),
                    message=(
                        f"Private key file '{private_key_file}' is empty."
                        if private_key_file
                        else "Private key content is empty."
                    ),
                )

            scope_list = (
                [s.strip() for s in scopes.split(",") if s.strip()]
                if scopes
                else list(DEFAULT_SCOPES)
            )

            return OktaSession(
                org_url=org_url,
                client_id=client_id,
                scopes=scope_list,
                private_key=private_key,
                kid=kid or None,
            )

        except (OktaInvalidOrgURLError, OktaPrivateKeyFileError):
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise OktaSetUpSessionError(original_exception=error)

    @staticmethod
    def setup_identity(session: OktaSession) -> OktaIdentityInfo:
        """Synthesize identity from the session and verify credentials.

        Service apps don't represent a human user, so the identity is the
        org URL plus the service-app client ID. We still hit the cheapest
        scope-covered endpoint (`list_policies` with limit=1) to fail loud
        when credentials, scopes, or the granted admin role are wrong.
        """

        async def _probe():
            config = {
                "orgUrl": session.org_url,
                "authorizationMode": "PrivateKey",
                "clientId": session.client_id,
                "scopes": session.scopes,
                "privateKey": session.private_key,
                # Send DPoP proofs on every token request. Required by tenants
                # that enable "Demonstrating Proof of Possession" on the
                # service app (or org-wide); harmless on tenants that don't.
                "dpopEnabled": True,
            }
            if session.kid:
                config["kid"] = session.kid
            client = OktaSDKClient(config)
            return await client.list_policies(type="OKTA_SIGN_ON", limit="1")

        try:
            result = asyncio.run(_probe())
            # SDK returns (items, resp, err) on the normal path and (items, err)
            # only on early request-creation errors. The error is always last.
            err = result[-1]
            if err is not None:
                raise OktaInvalidCredentialsError(
                    file=os.path.basename(__file__),
                    message=f"Failed to authenticate against Okta: {err}",
                )
            return OktaIdentityInfo(
                org_url=session.org_url,
                client_id=session.client_id,
            )
        except OktaInvalidCredentialsError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise OktaSetUpIdentityError(original_exception=error)

    def print_credentials(self):
        report_lines = [
            f"Okta Org URL: {Fore.YELLOW}{self.identity.org_url}{Style.RESET_ALL}",
            f"Okta Client ID: {Fore.YELLOW}{self.identity.client_id}{Style.RESET_ALL}",
            f"Authentication Method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the Okta credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        okta_org_url: str = "",
        okta_client_id: str = "",
        okta_private_key: str = "",
        okta_private_key_file: str = "",
        okta_scopes: str = "",
        okta_kid: str = "",
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test the connection to Okta with the provided OAuth credentials."""
        try:
            OktaProvider.validate_arguments(
                okta_org_url=okta_org_url,
                okta_client_id=okta_client_id,
                okta_private_key=okta_private_key,
                okta_private_key_file=okta_private_key_file,
            )
            session = OktaProvider.setup_session(
                org_url=okta_org_url,
                client_id=okta_client_id,
                private_key=okta_private_key,
                private_key_file=okta_private_key_file,
                scopes=okta_scopes,
                kid=okta_kid,
            )
            OktaProvider.setup_identity(session)
            return Connection(is_connected=True)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
