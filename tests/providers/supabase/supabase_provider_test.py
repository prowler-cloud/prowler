import os
from argparse import Namespace
from pathlib import Path
from unittest import mock

import pytest

from prowler.config.config import Provider as ProviderName
from prowler.lib.check.models import CheckReportSupabase
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.html.html import HTML
from prowler.providers.common.provider import Provider
from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAuthenticationError,
    SupabaseCredentialsError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
)
from prowler.providers.supabase.models import SupabaseOrganization, SupabaseSession
from prowler.providers.supabase.services.organizations.organizations_service import (
    SupabaseOrganizationMember,
)
from prowler.providers.supabase.supabase_provider import SupabaseProvider
from tests.providers.supabase.supabase_fixtures import (
    ACCESS_TOKEN,
    ORGANIZATION_ID,
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    USER_ID,
)


class TestSupabaseProvider:
    def test_setup_session_uses_environment_token(self):
        with mock.patch.dict(
            os.environ, {"SUPABASE_ACCESS_TOKEN": ACCESS_TOKEN}, clear=True
        ):
            session = SupabaseProvider.setup_session()

        assert session.access_token == ACCESS_TOKEN
        assert session.http_session.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"

    def test_setup_session_requires_environment_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SupabaseCredentialsError):
                SupabaseProvider.setup_session()

    def test_access_token_is_not_serialized_or_represented(self):
        session = SupabaseSession(access_token=ACCESS_TOKEN)

        assert ACCESS_TOKEN not in repr(session)
        assert ACCESS_TOKEN not in str(session)
        assert ACCESS_TOKEN not in session.model_dump_json()
        assert "access_token" not in session.model_dump()

    def test_setup_identity_lists_organizations_without_member_pii(self):
        session = SupabaseSession(
            access_token=ACCESS_TOKEN,
            http_session=mock.MagicMock(),
        )
        response = mock.MagicMock(status_code=200)
        response.json.return_value = [
            {
                "id": ORGANIZATION_ID,
                "name": ORGANIZATION_NAME,
                "slug": ORGANIZATION_SLUG,
            }
        ]
        session.http_session.get.return_value = response

        identity = SupabaseProvider.setup_identity(session, max_retries=0)

        assert identity.organizations[0].slug == ORGANIZATION_SLUG
        session.http_session.get.assert_called_once_with(
            "https://api.supabase.com/v1/organizations", timeout=30
        )

    @pytest.mark.parametrize(
        ("status_code", "exception"),
        [
            (401, SupabaseAuthenticationError),
            (403, SupabaseInsufficientPermissionsError),
            (429, SupabaseRateLimitError),
        ],
    )
    def test_setup_identity_preserves_management_api_errors(
        self, status_code, exception
    ):
        session = SupabaseSession(
            access_token=ACCESS_TOKEN,
            http_session=mock.MagicMock(),
        )
        session.http_session.get.return_value = mock.MagicMock(
            status_code=status_code,
            headers={"X-RateLimit-Reset": "0"},
        )

        with pytest.raises(exception):
            SupabaseProvider.setup_identity(session, max_retries=0)

    def test_from_cli_args_uses_environment_only(self):
        arguments = Namespace(
            config_file=None,
            mutelist_file=None,
        )

        with (
            mock.patch.dict(
                os.environ, {"SUPABASE_ACCESS_TOKEN": ACCESS_TOKEN}, clear=True
            ),
            mock.patch.object(
                SupabaseProvider,
                "setup_identity",
                return_value=mock.MagicMock(organizations=[]),
            ),
        ):
            provider = SupabaseProvider.from_cli_args(arguments, fixer_config={})

        assert provider.type == "supabase"
        assert not hasattr(arguments, "supabase_access_token")

    def test_parser_discovers_supabase_without_secret_argument(self):
        arguments = ProwlerArgumentParser().parse(
            ["prowler", "supabase", "--list-checks"]
        )

        assert arguments.provider == "supabase"
        assert not hasattr(arguments, "supabase_access_token")

    def test_provider_registry_and_class_resolution(self):
        assert ProviderName.SUPABASE.value == "supabase"
        assert Provider.get_class("supabase") is SupabaseProvider
        assert SupabaseProvider.sdk_only is True


class TestSupabaseProviderOutputHooks:
    def test_finding_output_uses_organization_and_member_ids(self):
        provider = SupabaseProvider.__new__(SupabaseProvider)
        provider._identity = mock.MagicMock(organizations=[])
        check_output = mock.MagicMock(
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            resource_name="member user-id",
            resource_id="user-id",
        )

        output = provider.get_finding_output_data(check_output)

        assert output == {
            "auth_method": "personal_access_token",
            "account_uid": ORGANIZATION_SLUG,
            "account_name": ORGANIZATION_NAME,
            "resource_name": "member user-id",
            "resource_uid": "user-id",
            "region": "global",
        }

    def test_finding_output_pipeline_uses_supabase_fields(self):
        provider = SupabaseProvider.__new__(SupabaseProvider)
        provider._identity = mock.MagicMock(organizations=[])
        member = SupabaseOrganizationMember(
            id=USER_ID,
            name=f"member {USER_ID}",
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            mfa_enabled=False,
        )
        metadata = Path(
            "prowler/providers/supabase/services/organizations/"
            "organizations_member_mfa_enabled/"
            "organizations_member_mfa_enabled.metadata.json"
        ).read_text()
        check_output = CheckReportSupabase(metadata=metadata, resource=member)
        check_output.status = "FAIL"
        check_output.status_extended = "Member does not have MFA enabled."

        finding = Finding.generate_output(
            provider, check_output, Namespace(unix_timestamp=False)
        )

        assert finding.provider == "supabase"
        assert finding.account_uid == ORGANIZATION_SLUG
        assert finding.account_name == ORGANIZATION_NAME
        assert finding.resource_name == f"member {USER_ID}"
        assert finding.resource_uid == USER_ID
        assert finding.region == "global"
        assert finding.auth_method == "personal_access_token"

    @pytest.mark.parametrize(
        ("output_filename", "expected"),
        [
            (None, f"prowler-output-{ORGANIZATION_SLUG}-"),
            ("custom-report", "custom-report"),
        ],
    )
    def test_output_options_use_organization_slug_or_explicit_name(
        self, output_filename, expected
    ):
        provider = SupabaseProvider.__new__(SupabaseProvider)
        provider._identity = mock.MagicMock(
            organizations=[
                SupabaseOrganization(
                    id=ORGANIZATION_ID,
                    name=ORGANIZATION_NAME,
                    slug=ORGANIZATION_SLUG,
                )
            ]
        )

        output_options = provider.get_output_options(
            Namespace(output_filename=output_filename), {}
        )

        if output_filename:
            assert output_options.output_filename == expected
        else:
            assert output_options.output_filename.startswith(expected)

    def test_html_assessment_summary_uses_supabase_hook(self):
        provider = SupabaseProvider.__new__(SupabaseProvider)
        provider._identity = mock.MagicMock(
            organizations=[
                SupabaseOrganization(
                    id=ORGANIZATION_ID,
                    name=ORGANIZATION_NAME,
                    slug=ORGANIZATION_SLUG,
                )
            ]
        )

        summary = HTML.get_assessment_summary(provider)

        assert "Supabase Assessment Summary" in summary
        assert f"<b>Organizations:</b> {ORGANIZATION_SLUG}" in summary
        assert "<b>Authentication:</b> Personal Access Token" in summary

    def test_summary_and_stdout_hooks_are_global(self):
        provider = SupabaseProvider.__new__(SupabaseProvider)
        provider._identity = mock.MagicMock(
            organizations=[
                SupabaseOrganization(
                    id=ORGANIZATION_ID,
                    name=ORGANIZATION_NAME,
                    slug=ORGANIZATION_SLUG,
                )
            ]
        )

        assert provider.get_summary_entity() == (
            "Organization",
            f"{ORGANIZATION_NAME} ({ORGANIZATION_SLUG})",
        )
        assert provider.get_stdout_detail(mock.MagicMock()) == "global"
