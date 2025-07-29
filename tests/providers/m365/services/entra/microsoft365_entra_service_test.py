from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.entra.entra_service import (
    AdminConsentPolicy,
    AdminRoles,
    ApplicationsConditions,
    AuthenticationStrength,
    AuthorizationPolicy,
    AuthPolicyRoles,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    DefaultUserRolePermissions,
    Entra,
    GrantControlOperator,
    GrantControls,
    InvitationsFrom,
    Organization,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    SignInFrequencyType,
    User,
    UserAction,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


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
        guest_invite_settings=InvitationsFrom.ADMINS_AND_GUEST_INVITERS.value,
        guest_user_role_id=AuthPolicyRoles.GUEST_USER_ACCESS_RESTRICTED.value,
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
                    included_user_actions=[UserAction.REGISTER_SECURITY_INFO],
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
                built_in_controls=[
                    ConditionalAccessGrantControl.BLOCK,
                    ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                ],
                operator=GrantControlOperator.OR,
                authentication_strength=AuthenticationStrength.PHISHING_RESISTANT_MFA,
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


async def mock_entra_get_groups(_):
    group1 = {
        "id": "id-1",
        "name": "group1",
        "groupTypes": ["DynamicMembership"],
        "membershipRule": 'user.userType -eq "Guest"',
    }
    group2 = {
        "id": "id-2",
        "name": "group2",
        "groupTypes": ["Assigned"],
        "membershipRule": "",
    }
    return [group1, group2]


async def mock_entra_get_admin_consent_policy(_):
    return AdminConsentPolicy(
        admin_consent_enabled=True,
        notify_reviewers=True,
        email_reminders_to_reviewers=False,
        duration_in_days=30,
    )


async def mock_entra_get_users(_):
    return {
        "user-1": User(
            id="user-1",
            name="User 1",
            directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
            on_premises_sync_enabled=True,
            is_mfa_capable=True,
        ),
        "user-2": User(
            id="user-2",
            name="User 2",
            directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
            on_premises_sync_enabled=False,
            is_mfa_capable=False,
        ),
        "user-3": User(
            id="user-3",
            name="User 3",
            directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
            on_premises_sync_enabled=True,
            is_mfa_capable=False,
        ),
    }


async def mock_entra_get_organization(_):
    return [
        Organization(
            id="org1",
            name="Organization 1",
            on_premises_sync_enabled=True,
        )
    ]


class Test_Entra_Service:
    def test_get_client(self):
        admincenter_client = Entra(
            set_mocked_m365_provider(identity=M365IdentityInfo(tenant_domain=DOMAIN))
        )
        assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_authorization_policy",
        new=mock_entra_get_authorization_policy,
    )
    def test_get_authorization_policy(self):
        entra_client = Entra(set_mocked_m365_provider())
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
        assert (
            entra_client.authorization_policy.guest_invite_settings
            == InvitationsFrom.ADMINS_AND_GUEST_INVITERS.value
        )
        assert (
            entra_client.authorization_policy.guest_user_role_id
            == AuthPolicyRoles.GUEST_USER_ACCESS_RESTRICTED.value
        )

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_conditional_access_policies",
        new=mock_entra_get_conditional_access_policies,
    )
    def test_get_conditional_access_policies(self):
        entra_client = Entra(set_mocked_m365_provider())
        assert entra_client.conditional_access_policies == {
            "id-1": ConditionalAccessPolicy(
                id="id-1",
                display_name="Name 1",
                conditions=Conditions(
                    application_conditions=ApplicationsConditions(
                        included_applications=["app-1", "app-2"],
                        excluded_applications=["app-3", "app-4"],
                        included_user_actions=[UserAction.REGISTER_SECURITY_INFO],
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
                    built_in_controls=[
                        ConditionalAccessGrantControl.BLOCK,
                        ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                    ],
                    operator=GrantControlOperator.OR,
                    authentication_strength=AuthenticationStrength.PHISHING_RESISTANT_MFA,
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

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_groups",
        new=mock_entra_get_groups,
    )
    def test_get_groups(self):
        entra_client = Entra(set_mocked_m365_provider())
        assert len(entra_client.groups) == 2
        assert entra_client.groups[0]["id"] == "id-1"
        assert entra_client.groups[0]["name"] == "group1"
        assert entra_client.groups[0]["groupTypes"] == ["DynamicMembership"]
        assert entra_client.groups[0]["membershipRule"] == 'user.userType -eq "Guest"'
        assert entra_client.groups[1]["id"] == "id-2"
        assert entra_client.groups[1]["name"] == "group2"
        assert entra_client.groups[1]["groupTypes"] == ["Assigned"]
        assert entra_client.groups[1]["membershipRule"] == ""

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_admin_consent_policy",
        new=mock_entra_get_admin_consent_policy,
    )
    def test_get_admin_consent_policy(self):
        entra_client = Entra(set_mocked_m365_provider())
        assert entra_client.admin_consent_policy.admin_consent_enabled
        assert entra_client.admin_consent_policy.notify_reviewers
        assert entra_client.admin_consent_policy.email_reminders_to_reviewers is False
        assert entra_client.admin_consent_policy.duration_in_days == 30

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_organization",
        new=mock_entra_get_organization,
    )
    def test_get_organization(self):
        entra_client = Entra(set_mocked_m365_provider())
        assert len(entra_client.organizations) == 1
        assert entra_client.organizations[0].id == "org1"
        assert entra_client.organizations[0].name == "Organization 1"
        assert entra_client.organizations[0].on_premises_sync_enabled

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_users",
        new=mock_entra_get_users,
    )
    def test_get_users(self):
        entra_client = Entra(set_mocked_m365_provider())
        assert len(entra_client.users) == 3
        assert entra_client.users["user-1"].id == "user-1"
        assert entra_client.users["user-1"].name == "User 1"
        assert entra_client.users["user-1"].directory_roles_ids == [
            AdminRoles.GLOBAL_ADMINISTRATOR.value
        ]
        assert entra_client.users["user-1"].is_mfa_capable
        assert entra_client.users["user-1"].on_premises_sync_enabled
        assert entra_client.users["user-2"].id == "user-2"
        assert entra_client.users["user-2"].name == "User 2"
        assert entra_client.users["user-2"].directory_roles_ids == [
            AdminRoles.GLOBAL_ADMINISTRATOR.value
        ]
        assert not entra_client.users["user-2"].is_mfa_capable
        assert not entra_client.users["user-2"].on_premises_sync_enabled
        assert entra_client.users["user-3"].id == "user-3"
        assert entra_client.users["user-3"].name == "User 3"
        assert entra_client.users["user-3"].directory_roles_ids == [
            AdminRoles.GLOBAL_ADMINISTRATOR.value
        ]
        assert entra_client.users["user-3"].on_premises_sync_enabled
        assert not entra_client.users["user-3"].is_mfa_capable
