from unittest import mock

from prowler.providers.supabase.services.organizations.organizations_service import (
    SupabaseOrganizationMember,
)
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    USER_ID,
    set_mocked_supabase_provider,
)


class Test_organizations_member_mfa_enabled:
    def _execute(self, members):
        organizations_client = mock.MagicMock()
        organizations_client.members = members

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_supabase_provider(),
            ),
            mock.patch(
                "prowler.providers.supabase.services.organizations.organizations_member_mfa_enabled.organizations_member_mfa_enabled.organizations_client",
                new=organizations_client,
            ),
        ):
            from prowler.providers.supabase.services.organizations.organizations_member_mfa_enabled.organizations_member_mfa_enabled import (
                organizations_member_mfa_enabled,
            )

            return organizations_member_mfa_enabled().execute()

    def test_no_members(self):
        assert self._execute({}) == []

    def test_member_with_mfa_passes_without_email(self):
        member = SupabaseOrganizationMember(
            id=USER_ID,
            name=f"member {USER_ID}",
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            mfa_enabled=True,
        )

        result = self._execute({f"{ORGANIZATION_SLUG}:{USER_ID}": member})

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == USER_ID
        assert result[0].organization_slug == ORGANIZATION_SLUG
        assert result[0].status_extended == (
            f"Supabase organization {ORGANIZATION_SLUG} member {USER_ID} has MFA enabled."
        )

    def test_member_without_mfa_fails(self):
        member = SupabaseOrganizationMember(
            id=USER_ID,
            name=f"member {USER_ID}",
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            mfa_enabled=False,
        )

        result = self._execute({f"{ORGANIZATION_SLUG}:{USER_ID}": member})

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == USER_ID
        assert result[0].status_extended == (
            f"Supabase organization {ORGANIZATION_SLUG} member {USER_ID} does not have MFA enabled."
        )

    def test_multiple_members_return_independent_pass_and_fail_findings(self):
        enabled_member = SupabaseOrganizationMember(
            id="enabled-user",
            name="member enabled-user",
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            mfa_enabled=True,
        )
        disabled_member = SupabaseOrganizationMember(
            id="disabled-user",
            name="member disabled-user",
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            mfa_enabled=False,
        )

        result = self._execute(
            {
                f"{ORGANIZATION_SLUG}:enabled-user": enabled_member,
                f"{ORGANIZATION_SLUG}:disabled-user": disabled_member,
            }
        )

        assert [(finding.resource_id, finding.status) for finding in result] == [
            ("enabled-user", "PASS"),
            ("disabled-user", "FAIL"),
        ]
