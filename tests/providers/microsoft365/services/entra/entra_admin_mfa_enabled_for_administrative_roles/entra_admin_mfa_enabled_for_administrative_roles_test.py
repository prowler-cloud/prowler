from unittest import mock
from uuid import uuid4

from prowler.providers.microsoft365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_entra_admin_mfa_enabled_for_administrative_roles:
    def test_no_conditional_access_policies(self):
        """No hay políticas configuradas: se espera FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {}

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requiring MFA for administrative roles was found."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_disabled(self):
        """Política en estado DISABLED: se espera que se omita y se retorne FAIL."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Disabled Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"], excluded_applications=[]
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requiring MFA for administrative roles was found."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_missing_admin_roles(self):
        """
        Política habilitada pero que no aplica a roles administrativos:
        No incluye 'All' en included_users ni los roles administrativos en included_roles.
        Se espera FAIL.
        """
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="No Admin Roles Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"], excluded_applications=[]
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requiring MFA for administrative roles was found."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_missing_application_all(self):
        """
        Política habilitada que incluye a usuarios administrativos (por 'All')
        pero no tiene "All" en included_applications.
        Se espera FAIL.
        """
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Missing Application All Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["MicrosoftAdminPortals"],
                            excluded_applications=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requiring MFA for administrative roles was found."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_valid(self):
        """
        Política válida:
         - Estado habilitado (ENABLED o ENABLED_FOR_REPORTING)
         - Aplica a roles administrativos mediante 'All' en included_users
         - Application conditions incluye "All"
         - MFA está configurado en grant_controls

         Se espera PASS.
        """
        policy_id = str(uuid4())
        display_name = "Valid MFA Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"], excluded_applications=[]
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            expected_status_extended = f"Conditional Access Policy '{display_name}' requires MFA for administrative roles."
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource == entra_client.conditional_access_policies
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_valid_through_roles(self):
        """
        Política válida:
         - Estado habilitado (ENABLED o ENABLED_FOR_REPORTING)
         - Aplica a roles administrativos mediante 'All' en included_users
         - Application conditions incluye "All"
         - MFA está configurado en grant_controls

         Se espera PASS.
        """
        policy_id = str(uuid4())
        display_name = "Valid MFA Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"], excluded_applications=[]
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[
                                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                                "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                                "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                                "158c047a-c907-4556-b7ef-446551a6b5f7",
                                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                                "29232cdf-9323-42fd-ade2-1d097af3e4de",
                                "62e90394-69f5-4237-9190-012177145e10",
                                "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
                                "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                                "966707d0-3269-4727-9be2-8c3a10f19b9d",
                                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                                "194ae4cb-b126-40b2-bd5b-6091b380977d",
                                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                                "fe930be7-5e62-47db-91af-98c3a49a38b1",
                            ],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            expected_status_extended = f"Conditional Access Policy '{display_name}' requires MFA for administrative roles."
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource == entra_client.conditional_access_policies
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_valid_one_missing_role(self):
        """
        Política válida:
         - Estado habilitado (ENABLED o ENABLED_FOR_REPORTING)
         - Aplica a roles administrativos mediante 'All' en included_users
         - Application conditions incluye "All"
         - MFA está configurado en grant_controls

         Se espera PASS.
        """
        policy_id = str(uuid4())
        display_name = "Valid MFA Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_mfa_enabled_for_administrative_roles.entra_admin_mfa_enabled_for_administrative_roles import (
                entra_admin_mfa_enabled_for_administrative_roles,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"], excluded_applications=[]
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[
                                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                                "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                                "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                                "158c047a-c907-4556-b7ef-446551a6b5f7",
                                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                                "29232cdf-9323-42fd-ade2-1d097af3e4de",
                                "62e90394-69f5-4237-9190-012177145e10",
                                "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
                                "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                                "966707d0-3269-4727-9be2-8c3a10f19b9d",
                                "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                                "194ae4cb-b126-40b2-bd5b-6091b380977d",
                                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                            ],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_admin_mfa_enabled_for_administrative_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            expected_status_extended = "No Conditional Access Policy requiring MFA for administrative roles was found."
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
