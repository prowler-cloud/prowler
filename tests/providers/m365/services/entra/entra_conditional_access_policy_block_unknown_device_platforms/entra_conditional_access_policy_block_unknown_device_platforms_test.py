from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    PlatformConditions,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms"

KNOWN_PLATFORMS = ["android", "iOS", "windows", "macOS", "linux"]


def _make_session_controls() -> SessionControls:
    """Return a minimal SessionControls instance for testing."""
    return SessionControls(
        persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
        sign_in_frequency=SignInFrequency(
            is_enabled=False,
            frequency=None,
            type=None,
            interval=SignInFrequencyInterval.EVERY_TIME,
        ),
    )


class Test_entra_conditional_access_policy_block_unknown_device_platforms:
    """Tests for the entra_conditional_access_policy_block_unknown_device_platforms check."""

    def test_no_conditional_access_policies(self):
        """Test FAIL when there are no Conditional Access policies."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        """Test FAIL when the only matching policy is disabled."""
        policy_id = str(uuid4())
        display_name = "Block Unknown Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=KNOWN_PLATFORMS,
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_enabled_for_reporting_only(self):
        """Test FAIL when the matching policy is only in report-only mode."""
        policy_id = str(uuid4())
        display_name = "Block Unknown Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=KNOWN_PLATFORMS,
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Block Unknown Platforms' reports blocking unknown or unsupported device platforms but does not enforce it."
            )
            assert result[0].resource_name == "Block Unknown Platforms"
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_no_platform_conditions(self):
        """Test FAIL when the policy has no platform conditions configured."""
        policy_id = str(uuid4())
        display_name = "Block Unknown Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=None,
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )

    def test_policy_does_not_include_all_platforms(self):
        """Test FAIL when the policy includes specific platforms instead of all."""
        policy_id = str(uuid4())
        display_name = "Block Specific Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_policy_missing_excluded_known_platforms(self):
        """Test FAIL when the policy includes all platforms but does not exclude all known ones."""
        policy_id = str(uuid4())
        display_name = "Incomplete Platform Exclusion"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Only exclude 3 of 5 known platforms
            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=["android", "iOS", "windows"],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_policy_no_block_grant_control(self):
        """Test FAIL when the policy has correct platform conditions but does not block."""
        policy_id = str(uuid4())
        display_name = "MFA Unknown Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=KNOWN_PLATFORMS,
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_policy_enabled_and_compliant(self):
        """Test PASS when an enabled policy blocks unknown device platforms correctly."""
        policy_id = str(uuid4())
        display_name = "Block Unknown Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=KNOWN_PLATFORMS,
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Block Unknown Platforms' blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource_name == "Block Unknown Platforms"
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_mixed_policies_report_only_and_enabled(self):
        """Test PASS when both report-only and enabled compliant policies exist."""
        report_policy_id = str(uuid4())
        enabled_policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_unknown_device_platforms.entra_conditional_access_policy_block_unknown_device_platforms import (
                entra_conditional_access_policy_block_unknown_device_platforms,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            base_conditions = Conditions(
                application_conditions=ApplicationsConditions(
                    included_applications=["All"],
                    excluded_applications=[],
                    included_user_actions=[],
                ),
                user_conditions=UsersConditions(
                    included_groups=[],
                    excluded_groups=[],
                    included_users=["All"],
                    excluded_users=[],
                    included_roles=[],
                    excluded_roles=[],
                ),
                client_app_types=[],
                user_risk_levels=[],
                platform_conditions=PlatformConditions(
                    include_platforms=["all"],
                    exclude_platforms=KNOWN_PLATFORMS,
                ),
            )
            grant_controls = GrantControls(
                built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                operator=GrantControlOperator.OR,
                authentication_strength=None,
            )

            entra_client.conditional_access_policies = {
                report_policy_id: ConditionalAccessPolicy(
                    id=report_policy_id,
                    display_name="Report Only Policy",
                    conditions=base_conditions,
                    grant_controls=grant_controls,
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
                enabled_policy_id: ConditionalAccessPolicy(
                    id=enabled_policy_id,
                    display_name="Enforced Block Policy",
                    conditions=base_conditions,
                    grant_controls=grant_controls,
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_block_unknown_device_platforms()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "Enforced Block Policy"
            assert result[0].resource_id == enabled_policy_id
