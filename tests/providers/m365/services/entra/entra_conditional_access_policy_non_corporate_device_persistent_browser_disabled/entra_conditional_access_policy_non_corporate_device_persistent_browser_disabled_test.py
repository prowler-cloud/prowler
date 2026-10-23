from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessPolicyState,
    Conditions,
    DeviceConditions,
    DeviceFilterMode,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled"


def _make_policy(
    policy_id,
    display_name,
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    included_applications=None,
    persistent_browser_enabled=True,
    persistent_browser_mode="never",
    device_filter_mode=None,
    device_filter_rule=None,
):
    """Create a ConditionalAccessPolicy with the given parameters."""
    from prowler.providers.m365.services.entra.entra_service import (
        ConditionalAccessPolicy,
    )

    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_applications or ["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=included_users or ["All"],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=[],
            user_risk_levels=[],
            device_conditions=DeviceConditions(
                device_filter_mode=device_filter_mode,
                device_filter_rule=device_filter_rule,
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=[],
            operator=GrantControlOperator.AND,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(
                is_enabled=persistent_browser_enabled,
                mode=persistent_browser_mode,
            ),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=None,
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled:
    """Tests for non-persistent browser session enforcement on non-corporate devices."""

    def test_no_conditional_access_policies(self):
        """Test FAIL when no conditional access policies exist."""
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {}
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces a non-persistent browser session for non-corporate devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        """Test FAIL when a qualifying policy is disabled."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Disabled Policy",
                    state=ConditionalAccessPolicyState.DISABLED,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule='device.isCompliant -ne True -or device.trustType -ne "ServerAD"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_enabled_for_reporting(self):
        """Test FAIL when policy is enabled for reporting but not enforcing."""
        policy_id = str(uuid4())
        display_name = "Reporting Only Policy"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule='device.isCompliant -ne True -or device.trustType -ne "ServerAD"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports a non-persistent browser session for non-corporate devices but does not enforce it."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_missing_all_users(self):
        """Test FAIL when policy does not target all users."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Limited Users Policy",
                    included_users=["user1@example.com"],
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -ne True",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_missing_all_applications(self):
        """Test FAIL when policy does not target all applications."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Limited Apps Policy",
                    included_applications=["Office365"],
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -ne True",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_persistent_browser_not_enabled(self):
        """Test FAIL when persistent browser session control is not enabled."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Browser Not Enabled Policy",
                    persistent_browser_enabled=False,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -ne True",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_persistent_browser_mode_always(self):
        """Test FAIL when persistent browser mode is 'always' instead of 'never'."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Always Persistent Policy",
                    persistent_browser_mode="always",
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -ne True",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_no_device_filter(self):
        """Test FAIL when policy has no device filter."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="No Device Filter Policy",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_device_filter_include_compliant(self):
        """Test PASS with include mode device filter targeting non-compliant devices."""
        policy_id = str(uuid4())
        display_name = "Non-Persistent Browser Include Filter"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule='device.isCompliant -ne True -or device.trustType -ne "ServerAD"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} enforces a non-persistent browser session for non-corporate devices."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_device_filter_exclude_compliant(self):
        """Test PASS with exclude mode device filter excluding corporate devices."""
        policy_id = str(uuid4())
        display_name = "Non-Persistent Browser Exclude Filter"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    device_filter_mode=DeviceFilterMode.EXCLUDE,
                    device_filter_rule='device.isCompliant -eq True -and device.trustType -eq "ServerAD"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_device_filter_unrelated_rule(self):
        """Test FAIL when device filter rule does not target corporate device properties."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Unrelated Filter Policy",
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule='device.displayName -contains "kiosk"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_device_filter_include_corporate_devices(self):
        """Test FAIL when include mode targets only corporate devices."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Corporate Devices Policy",
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -eq True",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_policy_device_filter_exclude_non_corporate_devices(self):
        """Test FAIL when exclude mode excludes non-corporate devices."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name="Exclude Unmanaged Devices Policy",
                    device_filter_mode=DeviceFilterMode.EXCLUDE,
                    device_filter_rule="device.isCompliant -eq False",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "Conditional Access Policies"

    def test_multiple_policies_one_compliant(self):
        """Test PASS when at least one policy among multiple is compliant."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        display_name_2 = "Compliant Non-Persistent Browser Policy"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(
                    policy_id=policy_id_1,
                    display_name="Non-Compliant Policy",
                    persistent_browser_enabled=False,
                ),
                policy_id_2: _make_policy(
                    policy_id=policy_id_2,
                    display_name=display_name_2,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule='device.trustType -ne "ServerAD"',
                ),
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name_2
            assert result[0].resource_id == policy_id_2

    def test_policy_with_trust_type_only(self):
        """Test PASS with device filter referencing only trustType."""
        policy_id = str(uuid4())
        display_name = "TrustType Filter Policy"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    device_filter_mode=DeviceFilterMode.EXCLUDE,
                    device_filter_rule='device.trustType -eq "ServerAD"',
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name

    def test_manual_when_error_and_no_qualifying_policy(self):
        """Test MANUAL when policies could not be read and no qualifying policy exists."""
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {}
            entra_client.conditional_access_policies_error = (
                "ODataError: Insufficient privileges"
            )

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be fully read" in result[0].status_extended
            assert "ODataError: Insufficient privileges" in result[0].status_extended
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_pass_even_with_error_when_qualifying_policy_found(self):
        """Test PASS when a qualifying enabled policy exists despite an error flag."""
        policy_id = str(uuid4())
        display_name = "Qualifying Despite Error"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -ne True",
                )
            }
            entra_client.conditional_access_policies_error = (
                "ODataError: partial failure"
            )

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_persistent_browser_mode_case_insensitive(self):
        """Test PASS when persistent browser mode is 'Never' (mixed case)."""
        policy_id = str(uuid4())
        display_name = "Mixed Case Never Policy"
        entra_client = mock.MagicMock()
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled.entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled import (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id=policy_id,
                    display_name=display_name,
                    persistent_browser_mode="Never",
                    device_filter_mode=DeviceFilterMode.INCLUDE,
                    device_filter_rule="device.isCompliant -eq False",
                )
            }
            entra_client.conditional_access_policies_error = None

            check = (
                entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
