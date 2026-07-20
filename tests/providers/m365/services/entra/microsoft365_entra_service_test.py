import asyncio
import importlib
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.entra import entra_service
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

AdminConsentPolicy = entra_service.AdminConsentPolicy
AdminRoles = entra_service.AdminRoles
ApplicationEnforcedRestrictions = entra_service.ApplicationEnforcedRestrictions
ApplicationsConditions = entra_service.ApplicationsConditions
AppManagementRestrictions = entra_service.AppManagementRestrictions
AuthorizationPolicy = entra_service.AuthorizationPolicy
AuthPolicyRoles = entra_service.AuthPolicyRoles
ConditionalAccessGrantControl = entra_service.ConditionalAccessGrantControl
ConditionalAccessPolicy = entra_service.ConditionalAccessPolicy
ConditionalAccessPolicyState = entra_service.ConditionalAccessPolicyState
Conditions = entra_service.Conditions
CredentialRestriction = entra_service.CredentialRestriction
DefaultAppManagementPolicy = entra_service.DefaultAppManagementPolicy
DefaultUserRolePermissions = entra_service.DefaultUserRolePermissions
Entra = entra_service.Entra
GrantControlOperator = entra_service.GrantControlOperator
GrantControls = entra_service.GrantControls
InvitationsFrom = entra_service.InvitationsFrom
Organization = entra_service.Organization
PersistentBrowser = entra_service.PersistentBrowser
SessionControls = entra_service.SessionControls
SignInFrequency = entra_service.SignInFrequency
SignInFrequencyInterval = entra_service.SignInFrequencyInterval
SignInFrequencyType = entra_service.SignInFrequencyType
User = entra_service.User
UserAction = entra_service.UserAction
UsersConditions = entra_service.UsersConditions


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
                authentication_strength="Phishing-resistant MFA",
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
                application_enforced_restrictions=ApplicationEnforcedRestrictions(
                    is_enabled=False
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


async def mock_entra_get_default_app_management_policy(_):
    return DefaultAppManagementPolicy(
        id="00000000-0000-0000-0000-000000000000",
        name="Default app management tenant policy",
        description="Default tenant policy that enforces app management restrictions.",
        is_enabled=True,
        application_restrictions=AppManagementRestrictions(
            password_credentials=[
                CredentialRestriction(
                    restriction_type="passwordAddition",
                    state="enabled",
                ),
                CredentialRestriction(
                    restriction_type="passwordLifetime",
                    state="enabled",
                    max_lifetime="P365D",
                ),
                CredentialRestriction(
                    restriction_type="customPasswordAddition",
                    state="enabled",
                ),
            ],
            key_credentials=[
                CredentialRestriction(
                    restriction_type="asymmetricKeyLifetime",
                    state="enabled",
                    max_lifetime="P365D",
                ),
            ],
        ),
    )


class Test_Entra_Service:
    def test_get_client(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
            admincenter_client = Entra(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_authorization_policy",
        new=mock_entra_get_authorization_policy,
    )
    def test_get_authorization_policy(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
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
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
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
                    authentication_strength="Phishing-resistant MFA",
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
                    application_enforced_restrictions=ApplicationEnforcedRestrictions(
                        is_enabled=False
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
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
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
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
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
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
            entra_client = Entra(set_mocked_m365_provider())
        assert len(entra_client.organizations) == 1
        assert entra_client.organizations[0].id == "org1"
        assert entra_client.organizations[0].name == "Organization 1"
        assert entra_client.organizations[0].on_premises_sync_enabled

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_default_app_management_policy",
        new=mock_entra_get_default_app_management_policy,
    )
    def test_get_default_app_management_policy(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
            entra_client = Entra(set_mocked_m365_provider())
        assert (
            entra_client.default_app_management_policy.id
            == "00000000-0000-0000-0000-000000000000"
        )
        assert (
            entra_client.default_app_management_policy.name
            == "Default app management tenant policy"
        )
        assert (
            entra_client.default_app_management_policy.description
            == "Default tenant policy that enforces app management restrictions."
        )
        assert entra_client.default_app_management_policy.is_enabled is True
        app_restrictions = (
            entra_client.default_app_management_policy.application_restrictions
        )
        assert len(app_restrictions.password_credentials) == 3
        assert (
            app_restrictions.password_credentials[0].restriction_type
            == "passwordAddition"
        )
        assert (
            app_restrictions.password_credentials[1].restriction_type
            == "passwordLifetime"
        )
        assert app_restrictions.password_credentials[1].max_lifetime == "P365D"
        assert (
            app_restrictions.password_credentials[2].restriction_type
            == "customPasswordAddition"
        )
        assert len(app_restrictions.key_credentials) == 1
        assert (
            app_restrictions.key_credentials[0].restriction_type
            == "asymmetricKeyLifetime"
        )
        assert app_restrictions.key_credentials[0].max_lifetime == "P365D"

    @patch(
        "prowler.providers.m365.services.entra.entra_service.Entra._get_users",
        new=mock_entra_get_users,
    )
    def test_get_users(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
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

    def test__get_users_paginates_through_next_links(self):
        entra_service = Entra.__new__(Entra)
        entra_service.user_accounts_status = {"user-6": {"AccountDisabled": True}}

        users_page_one = [
            SimpleNamespace(
                id="user-1",
                display_name="User 1",
                on_premises_sync_enabled=True,
                employee_hire_date=datetime(2026, 6, 10, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                id="user-2",
                display_name="User 2",
                on_premises_sync_enabled=False,
            ),
            SimpleNamespace(
                id="user-3",
                display_name="User 3",
                on_premises_sync_enabled=None,
            ),
            SimpleNamespace(
                id="user-4",
                display_name="User 4",
                on_premises_sync_enabled=True,
            ),
            SimpleNamespace(
                id="user-5",
                display_name="User 5",
                on_premises_sync_enabled=False,
            ),
        ]
        users_page_two = [
            SimpleNamespace(
                id="user-6",
                display_name="User 6",
                on_premises_sync_enabled=True,
            )
        ]

        users_response_page_one = SimpleNamespace(
            value=users_page_one,
            odata_next_link="next-link",
        )
        users_response_page_two = SimpleNamespace(
            value=users_page_two,
            odata_next_link=None,
        )

        users_with_url_builder = SimpleNamespace(
            get=AsyncMock(return_value=users_response_page_two)
        )
        with_url_mock = MagicMock(return_value=users_with_url_builder)

        users_builder = SimpleNamespace(
            get=AsyncMock(return_value=users_response_page_one),
            with_url=with_url_mock,
        )

        role_members_response = SimpleNamespace(
            value=[
                SimpleNamespace(id="user-1"),
                SimpleNamespace(id="user-6"),
            ]
        )
        members_builder = SimpleNamespace(
            get=AsyncMock(return_value=role_members_response)
        )
        directory_roles_builder = SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    value=[
                        SimpleNamespace(
                            id="role-1",
                            role_template_id="role-template-1",
                        )
                    ]
                )
            ),
            by_directory_role_id=MagicMock(
                return_value=SimpleNamespace(members=members_builder)
            ),
        )

        registration_details_response = SimpleNamespace(
            value=[
                SimpleNamespace(
                    id="user-1",
                    is_mfa_capable=True,
                    methods_registered=["fido2SecurityKey"],
                ),
                SimpleNamespace(
                    id="user-6",
                    is_mfa_capable=True,
                    methods_registered=["mobilePhone"],
                ),
            ],
            odata_next_link=None,
        )
        registration_details_builder = SimpleNamespace(
            get=AsyncMock(return_value=registration_details_response),
            with_url=MagicMock(
                return_value=SimpleNamespace(get=AsyncMock(return_value=None))
            ),
        )
        reports_builder = SimpleNamespace(
            authentication_methods=SimpleNamespace(
                user_registration_details=registration_details_builder
            )
        )

        entra_service.client = SimpleNamespace(
            users=users_builder,
            directory_roles=directory_roles_builder,
            reports=reports_builder,
        )

        users = asyncio.run(entra_service._get_users())

        assert len(users) == 6
        assert users_builder.get.await_count == 1
        # The Graph users.get() call must request accountEnabled, userType and
        # onPremisesSyncEnabled via $select. They are not part of the default
        # property set, and omitting them causes disabled guest users to leak
        # into checks like entra_users_mfa_capable (issue #10921).
        request_configuration = users_builder.get.await_args.kwargs[
            "request_configuration"
        ]
        assert set(request_configuration.query_parameters.select) == {
            "id",
            "displayName",
            "userType",
            "accountEnabled",
            "onPremisesSyncEnabled",
            "employeeHireDate",
        }
        with_url_mock.assert_called_once_with("next-link")
        assert users["user-1"].directory_roles_ids == ["role-template-1"]
        assert users["user-6"].directory_roles_ids == ["role-template-1"]
        # When Graph does not return accountEnabled (legacy SimpleNamespace
        # fixtures) we still honour the EXO PowerShell fallback for backwards
        # compatibility.
        assert users["user-6"].account_enabled is False
        assert users["user-1"].is_mfa_capable is True
        assert users["user-2"].is_mfa_capable is False
        assert users["user-1"].authentication_methods == ["fido2SecurityKey"]
        assert users["user-6"].authentication_methods == ["mobilePhone"]
        assert users["user-2"].authentication_methods == []
        assert users["user-1"].employee_hire_date == datetime(
            2026, 6, 10, tzinfo=timezone.utc
        )

    def test__get_users_uses_graph_account_enabled_for_disabled_guests(self):
        """Regression test for https://github.com/prowler-cloud/prowler/issues/10921.

        Disabled guest users do not appear in EXO's ``Get-User`` output, so the
        previous code resolved their ``account_enabled`` from the EXO map,
        defaulted it to ``True`` and surfaced them as failing findings in
        ``entra_users_mfa_capable``. The Graph ``accountEnabled`` value must be
        used as the source of truth so disabled guests are excluded.
        """
        entra_service = Entra.__new__(Entra)
        # Empty EXO map mirrors the production scenario where the disabled guest
        # is absent from Get-User results.
        entra_service.user_accounts_status = {}

        graph_users = [
            SimpleNamespace(
                id="member-1",
                display_name="Member User",
                on_premises_sync_enabled=False,
                account_enabled=True,
                user_type="Member",
            ),
            SimpleNamespace(
                id="guest-1",
                display_name="Disabled Guest",
                on_premises_sync_enabled=False,
                account_enabled=False,
                user_type="Guest",
            ),
            SimpleNamespace(
                id="guest-2",
                display_name="Enabled Guest",
                on_premises_sync_enabled=False,
                account_enabled=True,
                user_type="Guest",
            ),
        ]
        users_response = SimpleNamespace(
            value=graph_users,
            odata_next_link=None,
        )
        users_builder = SimpleNamespace(
            get=AsyncMock(return_value=users_response),
            with_url=MagicMock(),
        )
        directory_roles_builder = SimpleNamespace(
            get=AsyncMock(return_value=SimpleNamespace(value=[])),
            by_directory_role_id=MagicMock(),
        )
        registration_details_builder = SimpleNamespace(
            get=AsyncMock(return_value=SimpleNamespace(value=[], odata_next_link=None)),
            with_url=MagicMock(),
        )
        reports_builder = SimpleNamespace(
            authentication_methods=SimpleNamespace(
                user_registration_details=registration_details_builder
            )
        )

        entra_service.client = SimpleNamespace(
            users=users_builder,
            directory_roles=directory_roles_builder,
            reports=reports_builder,
        )

        users = asyncio.run(entra_service._get_users())

        assert len(users) == 3
        assert users["member-1"].account_enabled is True
        assert users["member-1"].user_type == "Member"
        assert users["guest-1"].account_enabled is False
        assert users["guest-1"].user_type == "Guest"
        assert users["guest-2"].account_enabled is True
        assert users["guest-2"].user_type == "Guest"

    def test__get_user_registration_details_handles_pagination(self):
        entra_service = Entra.__new__(Entra)

        registration_response_page_one = SimpleNamespace(
            value=[
                SimpleNamespace(
                    id="user-1",
                    is_mfa_capable=True,
                    methods_registered=[
                        "fido2SecurityKey",
                        "microsoftAuthenticatorPush",
                    ],
                ),
            ],
            odata_next_link="next-link",
        )
        registration_response_page_two = SimpleNamespace(
            value=[
                SimpleNamespace(
                    id="user-2", is_mfa_capable=False, methods_registered=[]
                ),
            ],
            odata_next_link=None,
        )

        registration_builder_next = SimpleNamespace(
            get=AsyncMock(return_value=registration_response_page_two)
        )
        registration_builder = SimpleNamespace(
            get=AsyncMock(return_value=registration_response_page_one),
            with_url=MagicMock(return_value=registration_builder_next),
        )

        entra_service.client = SimpleNamespace(
            reports=SimpleNamespace(
                authentication_methods=SimpleNamespace(
                    user_registration_details=registration_builder
                )
            )
        )

        registration_details, error_message = asyncio.run(
            entra_service._get_user_registration_details()
        )

        assert error_message is None
        assert registration_details == {
            "user-1": {
                "is_mfa_capable": True,
                "authentication_methods": [
                    "fido2SecurityKey",
                    "microsoftAuthenticatorPush",
                ],
            },
            "user-2": {
                "is_mfa_capable": False,
                "authentication_methods": [],
            },
        }
        registration_builder.get.assert_awaited()
        registration_builder.with_url.assert_called_once_with("next-link")
        registration_builder_next.get.assert_awaited()

    def test__get_user_registration_details_returns_error_on_permission_denied(self):
        """Test that 403 Authorization_RequestDenied returns an empty dict and
        a descriptive error message naming the missing AuditLog.Read.All permission.
        """
        from msgraph.generated.models.o_data_errors.main_error import MainError

        o_data_error = importlib.import_module(
            "msgraph.generated.models.o_data_errors.o_data_error"
        )

        odata_error = o_data_error.ODataError()
        odata_error.error = MainError()
        odata_error.error.code = "Authorization_RequestDenied"

        registration_builder = SimpleNamespace(get=AsyncMock(side_effect=odata_error))

        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            reports=SimpleNamespace(
                authentication_methods=SimpleNamespace(
                    user_registration_details=registration_builder
                )
            )
        )

        registration_details, error_message = asyncio.run(
            entra_service._get_user_registration_details()
        )

        assert registration_details == {}
        assert error_message is not None
        assert "AuditLog.Read.All" in error_message
        assert "user registration details" in error_message

    def test__get_service_principals_filters_third_party_owners(self):
        """Service principals owned by another tenant must not be returned."""
        # Mixed-case input to verify the service normalizes both sides before
        # comparison, so a Graph response that returns the owner id in upper
        # case still matches the lower-case identity in the provider.
        tenant_id_in = "AAAAAAAA-1111-1111-1111-111111111111"
        tenant_id_lower = tenant_id_in.lower()
        microsoft_tenant_id = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

        owned_sp = SimpleNamespace(
            id="sp-owned",
            display_name="Customer App",
            app_id="app-owned",
            app_owner_organization_id=tenant_id_in,
            password_credentials=[
                SimpleNamespace(
                    key_id="cred-1",
                    display_name="secret",
                    end_date_time=None,
                )
            ],
            key_credentials=[],
        )
        first_party_sp = SimpleNamespace(
            id="sp-first-party",
            display_name="Microsoft Graph",
            app_id="app-graph",
            app_owner_organization_id=microsoft_tenant_id,
            password_credentials=[
                SimpleNamespace(
                    key_id="cred-2",
                    display_name="secret",
                    end_date_time=None,
                )
            ],
            key_credentials=[],
        )
        third_party_sp = SimpleNamespace(
            id="sp-third-party",
            display_name="Some Vendor App",
            app_id="app-vendor",
            app_owner_organization_id="22222222-2222-2222-2222-222222222222",
            password_credentials=[],
            key_credentials=[],
        )

        sp_response = SimpleNamespace(
            value=[owned_sp, first_party_sp, third_party_sp],
            odata_next_link=None,
        )

        empty_assignments_response = SimpleNamespace(value=[], odata_next_link=None)

        role_assignments_builder = SimpleNamespace(
            get=AsyncMock(return_value=empty_assignments_response)
        )
        role_management_builder = SimpleNamespace(
            directory=SimpleNamespace(
                role_assignments=role_assignments_builder,
            )
        )

        service_principals_builder = SimpleNamespace(
            get=AsyncMock(return_value=sp_response),
            with_url=MagicMock(),
        )

        # The /applications endpoint returns no entries for this case, so the
        # service-level test just exercises the customer-owned filter, not the
        # secret join.
        applications_response = SimpleNamespace(value=[], odata_next_link=None)
        applications_builder = SimpleNamespace(
            get=AsyncMock(return_value=applications_response),
            with_url=MagicMock(),
        )

        entra_service = Entra.__new__(Entra)
        entra_service.tenant_id = tenant_id_lower
        entra_service.client = SimpleNamespace(
            service_principals=service_principals_builder,
            role_management=role_management_builder,
            applications=applications_builder,
        )

        result = asyncio.run(entra_service._get_service_principals())

        assert set(result.keys()) == {"sp-owned"}
        assert result["sp-owned"].app_owner_organization_id == tenant_id_lower

    def test__get_service_principals_merges_application_credentials(self):
        """Secrets registered on the parent Application must be attributed to the SP."""
        tenant_id = "11111111-1111-1111-1111-111111111111"

        # SP returned by Graph with NO password_credentials of its own (the
        # common case in production when the secret was added through "App
        # registrations > Certificates & secrets").
        sp_without_sp_level_secret = SimpleNamespace(
            id="sp-owned",
            display_name="m365-dev",
            app_id="app-owned",
            app_owner_organization_id=tenant_id,
            password_credentials=[],
            key_credentials=[],
        )
        sp_response = SimpleNamespace(
            value=[sp_without_sp_level_secret], odata_next_link=None
        )

        # The corresponding Application carries the actual secret.
        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        application = SimpleNamespace(
            id="app-object",
            app_id="app-owned",
            password_credentials=[
                SimpleNamespace(
                    key_id="cred-app",
                    display_name="app-level-secret",
                    end_date_time=future,
                ),
            ],
            key_credentials=[],
        )
        applications_response = SimpleNamespace(
            value=[application], odata_next_link=None
        )

        empty_assignments_response = SimpleNamespace(value=[], odata_next_link=None)

        entra_service = Entra.__new__(Entra)
        entra_service.tenant_id = tenant_id
        entra_service.client = SimpleNamespace(
            service_principals=SimpleNamespace(
                get=AsyncMock(return_value=sp_response),
                with_url=MagicMock(),
            ),
            applications=SimpleNamespace(
                get=AsyncMock(return_value=applications_response),
                with_url=MagicMock(),
            ),
            role_management=SimpleNamespace(
                directory=SimpleNamespace(
                    role_assignments=SimpleNamespace(
                        get=AsyncMock(return_value=empty_assignments_response),
                    ),
                )
            ),
        )

        result = asyncio.run(entra_service._get_service_principals())

        merged = result["sp-owned"]
        assert len(merged.password_credentials) == 1
        assert merged.password_credentials[0].key_id == "cred-app"
        assert merged.password_credentials[0].display_name == "app-level-secret"
        assert merged.password_credentials[0].is_active()

    def test__get_exchange_mailbox_permission_service_principals(self):
        """Service principals with Exchange Graph application roles are returned."""
        graph_sp_id = "graph-sp-id"
        mail_read_role_id = "11111111-1111-1111-1111-111111111111"
        user_read_role_id = "22222222-2222-2222-2222-222222222222"

        graph_sp = SimpleNamespace(
            id=graph_sp_id,
            display_name="Microsoft Graph",
            app_id="00000003-0000-0000-c000-000000000000",
            app_owner_organization_id="f8cdef31-a31e-4b4a-93e4-5f571e91255a",
            app_roles=[
                SimpleNamespace(
                    id=mail_read_role_id,
                    value="Mail.Read",
                    allowed_member_types=["Application"],
                ),
                SimpleNamespace(
                    id=user_read_role_id,
                    value="User.Read.All",
                    allowed_member_types=["Application"],
                ),
            ],
            account_enabled=True,
            service_principal_type="Application",
        )
        mailbox_app = SimpleNamespace(
            id="sp-mailbox",
            display_name="Mailbox App",
            app_id="app-mailbox",
            app_owner_organization_id="33333333-3333-3333-3333-333333333333",
            app_roles=[],
            account_enabled=True,
            service_principal_type="Application",
        )
        disabled_app = SimpleNamespace(
            id="sp-disabled",
            display_name="Disabled App",
            app_id="app-disabled",
            app_owner_organization_id="33333333-3333-3333-3333-333333333333",
            app_roles=[],
            account_enabled=False,
            service_principal_type="Application",
        )
        first_party_app = SimpleNamespace(
            id="sp-first-party",
            display_name="Microsoft App",
            app_id="app-first-party",
            app_owner_organization_id="f8cdef31-a31e-4b4a-93e4-5f571e91255a",
            app_roles=[],
            account_enabled=True,
            service_principal_type="Application",
        )

        app_role_assignments = {
            "sp-mailbox": SimpleNamespace(
                value=[
                    SimpleNamespace(
                        resource_id=graph_sp_id,
                        app_role_id=mail_read_role_id,
                    ),
                    SimpleNamespace(
                        resource_id=graph_sp_id,
                        app_role_id=user_read_role_id,
                    ),
                ],
                odata_next_link=None,
            )
        }

        def by_service_principal_id(service_principal_id):
            return SimpleNamespace(
                app_role_assignments=SimpleNamespace(
                    get=AsyncMock(
                        return_value=app_role_assignments.get(
                            service_principal_id,
                            SimpleNamespace(value=[], odata_next_link=None),
                        )
                    ),
                    with_url=MagicMock(),
                )
            )

        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            service_principals=SimpleNamespace(
                get=AsyncMock(
                    return_value=SimpleNamespace(
                        value=[graph_sp, mailbox_app, disabled_app, first_party_app],
                        odata_next_link=None,
                    )
                ),
                with_url=MagicMock(),
                by_service_principal_id=MagicMock(side_effect=by_service_principal_id),
            )
        )

        result = asyncio.run(
            entra_service._get_exchange_mailbox_permission_service_principals()
        )

        assert set(result.keys()) == {"sp-mailbox"}
        assert result["sp-mailbox"].app_id == "app-mailbox"
        assert result["sp-mailbox"].exchange_mailbox_permissions == ["Mail.Read"]

    def test__get_exchange_mailbox_permission_service_principals_records_error(self):
        """
        Graph collection failures preserve unavailable state separately from empty results.
        """
        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            service_principals=SimpleNamespace(
                get=AsyncMock(side_effect=RuntimeError("Graph unavailable"))
            )
        )

        result = asyncio.run(
            entra_service._get_exchange_mailbox_permission_service_principals()
        )

        assert result == {}
        assert "RuntimeError" in (
            entra_service.exchange_mailbox_permission_service_principals_error
        )
        assert "Graph unavailable" in (
            entra_service.exchange_mailbox_permission_service_principals_error
        )

    def test__resolve_identifiers_for_type_flags_only_404(self):
        """Only HTTP 404 / Request_ResourceNotFound mark an id as deleted.

        Transient errors (5xx, throttling) and successful resolutions must
        never be added to the unresolved set — that is the contract the check
        relies on to avoid false positives during Graph outages.
        """
        from msgraph.generated.models.o_data_errors.main_error import MainError
        from msgraph.generated.models.o_data_errors.o_data_error import ODataError

        deleted_by_status = "deleted-status-404"
        deleted_by_code = "deleted-code-rnf"
        transient = "transient-503"
        live = "live-user"

        error_404 = ODataError()
        error_404.response_status_code = 404
        error_404.error = None  # status code alone is enough

        error_rnf = ODataError()
        error_rnf.response_status_code = None
        error_rnf.error = MainError()
        error_rnf.error.code = "Request_ResourceNotFound"

        error_503 = ODataError()
        error_503.response_status_code = 503
        error_503.error = MainError()
        error_503.error.code = "ServiceUnavailable"

        user_builders = {
            deleted_by_status: SimpleNamespace(get=AsyncMock(side_effect=error_404)),
            deleted_by_code: SimpleNamespace(get=AsyncMock(side_effect=error_rnf)),
            transient: SimpleNamespace(get=AsyncMock(side_effect=error_503)),
            live: SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(id=live))),
        }

        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            users=SimpleNamespace(
                by_user_id=MagicMock(side_effect=lambda uid: user_builders[uid])
            )
        )

        unresolved = set()
        errored = set()
        asyncio.run(
            entra_service._resolve_identifiers_for_type(
                "user", set(user_builders), unresolved, errored
            )
        )

        assert unresolved == {
            ("user", deleted_by_status),
            ("user", deleted_by_code),
        }
        # The transient 503 must be recorded as errored (unverified), never as
        # deleted and never silently dropped.
        assert errored == {("user", transient)}

    def test__resolve_identifiers_for_type_role_uses_role_definitions_endpoint(self):
        """A deleted role is resolved against the roleDefinitions endpoint."""
        from msgraph.generated.models.o_data_errors.o_data_error import ODataError

        deleted_role = "deleted-role-id"

        error_404 = ODataError()
        error_404.response_status_code = 404
        error_404.error = None

        by_role_id = MagicMock(
            return_value=SimpleNamespace(get=AsyncMock(side_effect=error_404))
        )

        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            role_management=SimpleNamespace(
                directory=SimpleNamespace(
                    role_definitions=SimpleNamespace(
                        by_unified_role_definition_id=by_role_id
                    )
                )
            )
        )

        unresolved = set()
        errored = set()
        asyncio.run(
            entra_service._resolve_identifiers_for_type(
                "role", {deleted_role}, unresolved, errored
            )
        )

        assert unresolved == {("role", deleted_role)}
        assert errored == set()
        by_role_id.assert_called_once_with(deleted_role)

    def test__resolve_directory_object_references_skips_sentinels_and_dedups(self):
        """End-to-end resolver: sentinels are never queried, ids are deduped
        across policies, and only deleted ids land in the unresolved set."""
        from msgraph.generated.models.o_data_errors.o_data_error import ODataError

        deleted_user = "deleted-user-id"
        live_user = "live-user-id"
        deleted_group = "deleted-group-id"
        errored_group = "errored-group-id"

        def _user_conditions(**kwargs):
            base = {
                "included_users": [],
                "excluded_users": [],
                "included_groups": [],
                "excluded_groups": [],
                "included_roles": [],
                "excluded_roles": [],
            }
            base.update(kwargs)
            return SimpleNamespace(**base)

        def _policy(user_conditions):
            return SimpleNamespace(
                conditions=SimpleNamespace(user_conditions=user_conditions)
            )

        policies = {
            "policy-a": _policy(
                _user_conditions(
                    included_users=["All", deleted_user, live_user],
                    excluded_groups=[deleted_group, errored_group],
                )
            ),
            # Same deleted_user referenced again — must be resolved only once.
            "policy-b": _policy(
                _user_conditions(
                    included_users=[deleted_user],
                    excluded_users=["GuestsOrExternalUsers"],
                )
            ),
            # Policy without user conditions must be skipped without error.
            "policy-c": SimpleNamespace(
                conditions=SimpleNamespace(user_conditions=None)
            ),
        }

        error_404 = ODataError()
        error_404.response_status_code = 404
        error_404.error = None

        error_503 = ODataError()
        error_503.response_status_code = 503
        error_503.error = None

        user_builders = {
            deleted_user: SimpleNamespace(get=AsyncMock(side_effect=error_404)),
            live_user: SimpleNamespace(
                get=AsyncMock(return_value=SimpleNamespace(id=live_user))
            ),
        }
        group_builders = {
            deleted_group: SimpleNamespace(get=AsyncMock(side_effect=error_404)),
            errored_group: SimpleNamespace(get=AsyncMock(side_effect=error_503)),
        }
        by_user_id = MagicMock(side_effect=lambda uid: user_builders[uid])
        by_group_id = MagicMock(side_effect=lambda gid: group_builders[gid])

        entra_service = Entra.__new__(Entra)
        entra_service.client = SimpleNamespace(
            users=SimpleNamespace(by_user_id=by_user_id),
            groups=SimpleNamespace(by_group_id=by_group_id),
        )

        unresolved, errored = asyncio.run(
            entra_service._resolve_directory_object_references(policies)
        )

        assert unresolved == {
            ("user", deleted_user),
            ("group", deleted_group),
        }
        # The 503 group is unverified, not deleted — it lands in errored.
        assert errored == {("group", errored_group)}
        # Sentinels are filtered before any Graph call; only the two real user
        # ids are queried, and the deduped deleted_user is queried exactly once.
        queried_users = {call.args[0] for call in by_user_id.call_args_list}
        assert queried_users == {deleted_user, live_user}
        assert user_builders[deleted_user].get.await_count == 1
