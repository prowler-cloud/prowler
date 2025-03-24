from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import (
    AuthorizationPolicy,
    AuthPolicyRoles,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_policy_guest_users_access_restrictions:
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
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest user access is not restricted to properties and memberships of their own directory objects"
            )
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].location == "global"

    def test_auth_policy_fail(self):
        """
        Test when an authorization policy exists but guest_user_role_id does not match
        any of the restricted roles: the check should FAIL.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy123",
                name="Auth Policy Test",
                description="Test policy",
                guest_user_role_id=AuthPolicyRoles.USER.value,
            )

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "policy123"
            assert result[0].resource_name == "Auth Policy Test"
            assert result[0].location == "global"
            assert result[0].status_extended == (
                "Guest user access is not restricted to properties and memberships of their own directory objects"
            )
            assert result[0].resource == entra_client.authorization_policy

    def test_auth_policy_pass_restricted(self):
        """
        Test when the authorization policy exists and guest_user_role_id is set to
        AuthPolicyRoles.GUEST_USER_ACCESS_RESTRICTED: the check should PASS.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy456",
                name="Auth Policy Restricted",
                description="Test policy",
                guest_user_role_id=AuthPolicyRoles.GUEST_USER_ACCESS_RESTRICTED.value,
            )

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "policy456"
            assert result[0].resource_name == "Auth Policy Restricted"
            assert result[0].location == "global"
            assert result[0].status_extended == (
                "Guest user access is restricted to properties and memberships of their own directory objects"
            )
            assert result[0].resource == entra_client.authorization_policy

    def test_auth_policy_pass_guest_user(self):
        """
        Test when the authorization policy exists and guest_user_role_id is set to
        AuthPolicyRoles.GUEST_USER: the check should PASS.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="policy789",
                name="Auth Policy Guest",
                description="Test policy",
                guest_user_role_id=AuthPolicyRoles.GUEST_USER.value,
            )

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "policy789"
            assert result[0].resource_name == "Auth Policy Guest"
            assert result[0].location == "global"
            assert result[0].status_extended == (
                "Guest user access is restricted to properties and memberships of their own directory objects"
            )
            assert result[0].resource == entra_client.authorization_policy
