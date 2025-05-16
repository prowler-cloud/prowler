import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthorizationPolicy,
    InvitationsFrom,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_policy_guest_invite_only_for_admin_roles:
    def test_no_auth_policy(self):
        """
        Test when there is no authorization policy (auth_policy is None):
        The check should return a report with FAIL status using default resource values.
        """
        entra_client = mock.MagicMock()
        entra_client.authorization_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest invitations are not restricted to users with specific administrative roles only."
            )
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource == {}

    def test_auth_policy_fail(self):
        """
        Test when an authorization policy exists but guest_invite_settings is not set to a restricted value:
        The check should FAIL.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy001",
                name="Auth Policy Test",
                description="Test policy",
                guest_invite_settings=InvitationsFrom.EVERYONE.value,
            )

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest invitations are not restricted to users with specific administrative roles only."
            )
            assert result[0].resource_id == "policy001"
            assert result[0].resource_name == "Auth Policy Test"
            assert result[0].location == "global"
            assert result[0].resource == entra_client.authorization_policy.dict()

    def test_auth_policy_pass_admins_and_guest_inviters(self):
        """
        Test when the authorization policy exists and guest_invite_settings is set to
        InvitationsFrom.ADMINS_AND_GUEST_INVITERS: the check should PASS.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy002",
                name="Auth Policy Restricted",
                description="Test policy",
                guest_invite_settings=InvitationsFrom.ADMINS_AND_GUEST_INVITERS.value,
            )

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest invitations are restricted to users with specific administrative roles only."
            )
            assert result[0].resource_id == "policy002"
            assert result[0].resource_name == "Auth Policy Restricted"
            assert result[0].location == "global"
            assert result[0].resource == entra_client.authorization_policy.dict()

    def test_auth_policy_pass_none(self):
        """
        Test when the authorization policy exists and guest_invite_settings is set to
        InvitationsFrom.NONE: the check should PASS.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy003",
                name="Auth Policy Restricted None",
                description="Test policy",
                guest_invite_settings=InvitationsFrom.NONE.value,
            )

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest invitations are restricted to users with specific administrative roles only."
            )
            assert result[0].resource_id == "policy003"
            assert result[0].resource_name == "Auth Policy Restricted None"
            assert result[0].location == "global"
            assert result[0].resource == entra_client.authorization_policy.dict()
