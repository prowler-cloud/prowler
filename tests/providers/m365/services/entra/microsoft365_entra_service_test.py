import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.entra.entra_service import (
    AdminConsentPolicy,
    AdminRoles,
    ApplicationEnforcedRestrictions,
    ApplicationsConditions,
    AppManagementRestrictions,
    AuthorizationPolicy,
    AuthPolicyRoles,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    CredentialRestriction,
    DefaultAppManagementPolicy,
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

        registration_details = asyncio.run(
            entra_service._get_user_registration_details()
        )

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
