from unittest import mock
from uuid import uuid4

from prowler.providers.microsoft365.services.entra.entra_service import (
    AuthorizationPolicy,
    DefaultUserRolePermissions,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_policy_restricts_user_consent_for_apps:
    def test_entra_empty_policy(self):
        """
        Test that the check fails when no authorization policy exists.

        This test mocks the 'entra_client.authorization_policy' as an empty dictionary.
        Expected result: The check returns FAIL with the extended message indicating that
        Entra allows users to consent apps accessing company data on their behalf.
        """
        entra_client = mock.MagicMock
        entra_client.authorization_policy = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra allows users to consent apps accessing company data on their behalf."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].location == "global"

    def test_entra_policy_allows_user_consent(self):
        """
        Test that the check fails when the authorization policy allows user consent.

        This test mocks the 'entra_client.authorization_policy' with a policy that includes
        a permission grant policy (e.g., "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
        that allows users to consent apps.
        Expected result: The check returns FAIL with the extended message indicating that
        Entra allows users to consent apps accessing company data on their behalf.
        """
        id = str(uuid4())
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test Policy",
                description="Test Policy Description",
                default_user_role_permissions=DefaultUserRolePermissions(
                    permission_grant_policies_assigned=[
                        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
                    ]
                ),
            )

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra allows users to consent apps accessing company data on their behalf."
            )
            assert result[0].resource == entra_client.authorization_policy.dict()
            assert result[0].resource_name == "Test Policy"
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_policy_restricts_user_consent(self):
        """
        Test that the check passes when the authorization policy restricts user consent.

        This test mocks the 'entra_client.authorization_policy' with a policy that does not include
        any permission grant policy allowing user consent (i.e., it lacks policies containing
        "ManagePermissionGrantsForSelf").
        Expected result: The check returns PASS with the extended message indicating that
        Entra does not allow users to consent apps accessing company data on their behalf.
        """
        id = str(uuid4())
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test Policy",
                description="Test Policy Description",
                default_user_role_permissions=DefaultUserRolePermissions(
                    permission_grant_policies_assigned=["SomeOtherPolicy"]
                ),
            )

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra does not allow users to consent apps accessing company data on their behalf."
            )
            assert result[0].resource == entra_client.authorization_policy.dict()
            assert result[0].resource_name == "Test Policy"
            assert result[0].resource_id == id
            assert result[0].location == "global"
