import os
from argparse import Namespace

import requests
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAPIError,
    SupabaseAuthenticationError,
    SupabaseCredentialsError,
    SupabaseIdentityError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
    SupabaseSessionError,
)
from prowler.providers.supabase.lib.mutelist.mutelist import SupabaseMutelist
from prowler.providers.supabase.lib.service.service import request_json
from prowler.providers.supabase.models import (
    SupabaseIdentityInfo,
    SupabaseOrganization,
    SupabaseOutputOptions,
    SupabaseSession,
)


class SupabaseProvider(Provider):
    """Hosted Supabase Cloud Management API provider."""

    _type = "supabase"
    _cli_help_text = "Supabase Provider (PoC)"
    sdk_only = True
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        access_token: str = None,
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        self._audit_config = config_content or load_and_validate_config_file(
            self._type, config_path or default_config_file_path
        )
        self._session = self.setup_session(access_token)
        self._identity = self.setup_identity(
            self._session, self._audit_config.get("max_retries", 3)
        )
        self._fixer_config = fixer_config
        self._mutelist = (
            SupabaseMutelist(mutelist_content=mutelist_content)
            if mutelist_content
            else SupabaseMutelist(
                mutelist_path=mutelist_path or get_default_mute_file_path(self.type)
            )
        )
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
    def mutelist(self):
        return self._mutelist

    @staticmethod
    def setup_session(access_token: str = None) -> SupabaseSession:
        """Create a Bearer-token Management API session."""
        token = access_token or os.environ.get("SUPABASE_ACCESS_TOKEN", "")
        if not token:
            raise SupabaseCredentialsError(file=os.path.basename(__file__))
        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                }
            )
            return SupabaseSession(
                access_token=token,
                http_session=http_session,
            )
        except Exception as error:
            raise SupabaseSessionError(
                file=os.path.basename(__file__), original_exception=error
            )

    @staticmethod
    def setup_identity(
        session: SupabaseSession, max_retries: int = 3
    ) -> SupabaseIdentityInfo:
        """List organizations to validate credentials and establish scan scope."""
        try:
            organizations = request_json(
                session, "/v1/organizations", max_retries=max_retries
            )
            return SupabaseIdentityInfo(
                organizations=[
                    SupabaseOrganization(
                        id=organization["id"],
                        slug=organization["slug"],
                        name=organization["name"],
                    )
                    for organization in organizations
                ]
            )
        except (
            SupabaseAuthenticationError,
            SupabaseInsufficientPermissionsError,
            SupabaseRateLimitError,
            SupabaseAPIError,
        ):
            raise
        except Exception as error:
            raise SupabaseIdentityError(
                file=os.path.basename(__file__), original_exception=error
            )

    @classmethod
    def from_cli_args(cls, arguments: Namespace, fixer_config: dict):
        """Create the provider from non-secret CLI configuration."""
        return cls(
            config_path=arguments.config_file,
            mutelist_path=arguments.mutelist_file,
            fixer_config=fixer_config,
        )

    def print_credentials(self) -> None:
        organizations = (
            ", ".join(organization.slug for organization in self.identity.organizations)
            or "none"
        )
        print_boxes(
            [
                f"Authentication: {Fore.YELLOW}Personal Access Token{Style.RESET_ALL}",
                f"Organizations: {Fore.YELLOW}{organizations}{Style.RESET_ALL}",
            ],
            f"{Style.BRIGHT}Using the Supabase credentials below:{Style.RESET_ALL}",
        )

    @staticmethod
    def test_connection(
        access_token: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test access to the Supabase organizations endpoint."""
        try:
            session = SupabaseProvider.setup_session(access_token)
            identity = SupabaseProvider.setup_identity(session, max_retries=0)
            if provider_id and provider_id not in {
                identifier
                for organization in identity.organizations
                for identifier in (organization.id, organization.slug)
            }:
                raise SupabaseIdentityError(
                    file=os.path.basename(__file__),
                    message=(
                        f"Supabase organization '{provider_id}' is not accessible "
                        "with the supplied token."
                    ),
                )
            return Connection(is_connected=True)
        except Exception as error:
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)

    def validate_arguments(self) -> None:
        return None

    def get_output_options(self, arguments, bulk_checks_metadata):
        return SupabaseOutputOptions(arguments, bulk_checks_metadata, self.identity)

    def get_stdout_detail(self, _finding) -> str:
        return "global"

    def get_summary_entity(self) -> tuple[str, str]:
        organizations = ", ".join(
            f"{organization.name} ({organization.slug})"
            for organization in self.identity.organizations
        )
        return "Organization", organizations or "No organizations"

    def get_finding_output_data(self, check_output) -> dict:
        return {
            "auth_method": "personal_access_token",
            "account_uid": check_output.organization_slug,
            "account_name": check_output.organization_name,
            "resource_name": check_output.resource_name,
            "resource_uid": check_output.resource_id,
            "region": "global",
        }

    def get_html_assessment_summary(self) -> str:
        organizations = (
            ", ".join(organization.slug for organization in self.identity.organizations)
            or "none"
        )
        return f"""
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Supabase Assessment Summary</div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item"><b>Organizations:</b> {organizations}</li>
                        <li class="list-group-item"><b>Authentication:</b> Personal Access Token</li>
                    </ul>
                </div>
            </div>"""
