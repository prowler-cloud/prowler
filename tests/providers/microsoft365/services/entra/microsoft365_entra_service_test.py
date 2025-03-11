from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.entra.entra_service import (
    ApplicationsConditions,
    AuthorizationPolicy,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    DefaultUserRolePermissions,
    Entra,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    SignInFrequencyType,
    UsersConditions,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


async def mock_entra_get_authorization_policy(_):
    return AuthorizationPolicy(
        id="id-1",
        name="Name 1",
        description="Description 1",
        default_user_role_permissions=DefaultUserRolePermissions(
            allowed_to_create_apps=True,
            allowed_to_create_security_groups=True,
            allowed_to_create_tenants=True,
            allowed_to_read_bitlocker_keys_for_owned_device=True,
            allowed_to_read_other_users=True,
        ),
    )


async def mock_entra_get_conditional_access_policies(_):
    return {
        "id-1": ConditionalAccessPolicy(
            id="id-1",
            display_name="Name 1",
            conditions=Conditions(
                application_conditions=ApplicationsConditions(
                    included_applications=["app-1", "app-2"],
                    excluded_applications=["app-3", "app-4"],
                ),
                user_conditions=UsersConditions(
                    included_groups=["group-1", "group-2"],
                    excluded_groups=["group-3", "group-4"],
                    included_users=["user-1", "user-2"],
                    excluded_users=["user-3", "user-4"],
                    included_roles=["role-1", "role-2"],
                    excluded_roles=["role-3", "role-4"],
                ),
            ),
            grant_controls=GrantControls(
                built_in_controls=[ConditionalAccessGrantControl.BLOCK]
            ),
            session_controls=SessionControls(
                persistent_browser=PersistentBrowser(
                    is_enabled=True,
                    mode="always",
                ),
                sign_in_frequency=SignInFrequency(
                    is_enabled=True,
                    frequency=24,
                    type=SignInFrequencyType.HOURS,
                    interval=SignInFrequencyInterval.TIME_BASED,
                ),
            ),
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
        )
    }


class Test_Entra_Service:
    def test_get_client(self):
        admincenter_client = Entra(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    @patch(
        "prowler.providers.microsoft365.services.entra.entra_service.Entra._get_authorization_policy",
        new=mock_entra_get_authorization_policy,
    )
    def test_get_authorization_policy(self):
        entra_client = Entra(set_mocked_microsoft365_provider())
        assert entra_client.authorization_policy.id == "id-1"
        assert entra_client.authorization_policy.name == "Name 1"
        assert entra_client.authorization_policy.description == "Description 1"
        assert (
            entra_client.authorization_policy.default_user_role_permissions
            == DefaultUserRolePermissions(
                allowed_to_create_apps=True,
                allowed_to_create_security_groups=True,
                allowed_to_create_tenants=True,
                allowed_to_read_bitlocker_keys_for_owned_device=True,
                allowed_to_read_other_users=True,
            )
        )

    @patch(
        "prowler.providers.microsoft365.services.entra.entra_service.Entra._get_conditional_access_policies",
        new=mock_entra_get_conditional_access_policies,
    )
    def test_get_conditional_access_policies(self):
        entra_client = Entra(set_mocked_microsoft365_provider())
        assert entra_client.conditional_access_policies == {
            "id-1": ConditionalAccessPolicy(
                id="id-1",
                display_name="Name 1",
                conditions=Conditions(
                    application_conditions=ApplicationsConditions(
                        included_applications=["app-1", "app-2"],
                        excluded_applications=["app-3", "app-4"],
                    ),
                    user_conditions=UsersConditions(
                        included_groups=["group-1", "group-2"],
                        excluded_groups=["group-3", "group-4"],
                        included_users=["user-1", "user-2"],
                        excluded_users=["user-3", "user-4"],
                        included_roles=["role-1", "role-2"],
                        excluded_roles=["role-3", "role-4"],
                    ),
                ),
                grant_controls=GrantControls(
                    built_in_controls=[ConditionalAccessGrantControl.BLOCK]
                ),
                session_controls=SessionControls(
                    persistent_browser=PersistentBrowser(
                        is_enabled=True,
                        mode="always",
                    ),
                    sign_in_frequency=SignInFrequency(
                        is_enabled=True,
                        frequency=24,
                        type=SignInFrequencyType.HOURS,
                        interval=SignInFrequencyInterval.TIME_BASED,
                    ),
                ),
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            )
        }
