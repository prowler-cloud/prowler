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

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked"

KNOWN_PLATFORMS = ["android", "ios", "windows", "macos", "linux"]


def _default_session_controls():
    return SessionControls(
        persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
        sign_in_frequency=SignInFrequency(
            is_enabled=False,
            frequency=None,
            type=None,
            interval=SignInFrequencyInterval.EVERY_TIME,
        ),
    )


def _default_conditions(**overrides):
    defaults = dict(
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
        platform_conditions=PlatformConditions(
            included_platforms=["All"],
            excluded_platforms=KNOWN_PLATFORMS,
        ),
        user_risk_levels=[],
    )
    defaults.update(overrides)
    return Conditions(**defaults)


def _default_grant_controls(**overrides):
    defaults = dict(
        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
        operator=GrantControlOperator.OR,
        authentication_strength=None,
    )
    defaults.update(overrides)
    return GrantControls(**defaults)


class Test_entra_conditional_access_policy_unknown_device_blocked:
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_unknown_device_blocked()
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
        display_name = "Block Unknown Devices"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
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
        display_name = "Block Unknown Devices"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' is configured to block unknown device platforms but is only in report-only mode."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_no_platform_conditions(self):
        """Test FAIL when the policy has no platform conditions."""
        policy_id = str(uuid4())
        display_name = "Block Without Platforms"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(platform_conditions=None),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
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

    def test_policy_does_not_include_all_platforms(self):
        """Test FAIL when the policy does not include all platforms."""
        policy_id = str(uuid4())
        display_name = "Partial Platform Block"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(
                        platform_conditions=PlatformConditions(
                            included_platforms=["android", "ios"],
                            excluded_platforms=[],
                        )
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource == {}

    def test_policy_missing_excluded_platforms(self):
        """Test FAIL when the policy does not exclude all five known platforms."""
        policy_id = str(uuid4())
        display_name = "Incomplete Exclusions"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(
                        platform_conditions=PlatformConditions(
                            included_platforms=["All"],
                            excluded_platforms=["android", "ios", "windows"],
                        )
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource == {}

    def test_policy_no_block_grant_control(self):
        """Test FAIL when the policy does not use block as grant control."""
        policy_id = str(uuid4())
        display_name = "MFA Instead of Block"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(),
                    grant_controls=_default_grant_controls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA]
                    ),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy blocks access from unknown or unsupported device platforms."
            )
            assert result[0].resource == {}

    def test_policy_enabled_and_compliant(self):
        """Test PASS when an enabled policy blocks unknown device platforms."""
        policy_id = str(uuid4())
        display_name = "Block Unknown Devices"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_unknown_device_blocked.entra_conditional_access_policy_unknown_device_blocked import (
                entra_conditional_access_policy_unknown_device_blocked,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_default_conditions(),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_unknown_device_blocked()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' blocks access from unknown or unsupported device platforms."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"
