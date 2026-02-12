from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_safe_attachments_policy_enabled:
    """Tests for the defender_safe_attachments_policy_enabled check."""

    def test_no_safe_attachments_policies(self):
        """Test when no Safe Attachments policies exist."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )

            defender_client.safe_attachments_policies = {}
            defender_client.safe_attachments_rules = {}

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_case1_only_builtin_policy(self):
        """Case 1: Only Built-in Protection Policy exists - always PASS."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                )
            }
            defender_client.safe_attachments_rules = {}

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is the only Safe Attachments policy" in result[0].status_extended
            assert "baseline protection for all users" in result[0].status_extended

    def test_case2_builtin_and_custom_properly_configured(self):
        """Case 2: Built-in + custom policy properly configured - both PASS."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
                SafeAttachmentsRule,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                ),
                "Custom Policy": SafeAttachmentsPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=False,
                ),
            }
            defender_client.safe_attachments_rules = {
                "Custom Policy": SafeAttachmentsRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=["Engineering"],
                    domains=["example.com"],
                )
            }

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Built-in policy PASS
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "PASS"
            assert (
                "provides baseline Safe Attachments protection"
                in builtin_result.status_extended
            )

            # Custom policy PASS
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "PASS"
            assert "is properly configured" in custom_result.status_extended
            assert "users: user@example.com" in custom_result.status_extended
            assert "groups: Engineering" in custom_result.status_extended
            assert "domains: example.com" in custom_result.status_extended
            assert "priority 0" in custom_result.status_extended

    def test_case3_builtin_pass_custom_misconfigured(self):
        """Case 3: Built-in PASS + custom policy misconfigured - Built-in PASS, custom FAIL."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
                SafeAttachmentsRule,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                ),
                "Custom Policy": SafeAttachmentsPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable=False,  # Misconfigured
                    action="Allow",  # Misconfigured
                    quarantine_tag="DefaultFullAccessPolicy",  # Misconfigured
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=False,
                ),
            }
            defender_client.safe_attachments_rules = {
                "Custom Policy": SafeAttachmentsRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Built-in policy still PASS
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "PASS"

            # Custom policy FAIL
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "FAIL"
            assert "is not properly configured" in custom_result.status_extended
            assert "priority 0" in custom_result.status_extended

    def test_custom_policy_without_rule_skipped(self):
        """Test that custom policies without associated rules are skipped."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
                SafeAttachmentsRule,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                ),
                "Custom Policy Without Rule": SafeAttachmentsPolicy(
                    name="Custom Policy Without Rule",
                    identity="Custom-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=False,
                ),
            }
            # Rule for a different policy
            defender_client.safe_attachments_rules = {
                "Other Policy": SafeAttachmentsRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            # Only Built-in policy should be in results
            assert len(result) == 1
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].status == "PASS"

    def test_custom_policy_with_disabled_rule(self):
        """Test when custom policy has proper settings but disabled rule (FAIL)."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
                SafeAttachmentsRule,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                ),
                "Custom Policy": SafeAttachmentsPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=False,
                ),
            }
            defender_client.safe_attachments_rules = {
                "Custom Policy": SafeAttachmentsRule(
                    state="Disabled",  # Disabled rule
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Built-in policy PASS
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "PASS"

            # Custom policy FAIL because rule is disabled
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "FAIL"
            assert "is not properly configured" in custom_result.status_extended

    def test_custom_policy_applies_to_all_users_when_no_scope(self):
        """Test that custom policy with no users/groups/domains shows 'all users'."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safe_attachments_policy_enabled.defender_safe_attachments_policy_enabled import (
                defender_safe_attachments_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeAttachmentsPolicy,
                SafeAttachmentsRule,
            )

            defender_client.safe_attachments_policies = {
                "Built-In Protection Policy": SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=True,
                ),
                "Houston Safe Attachments Policy test": SafeAttachmentsPolicy(
                    name="Houston Safe Attachments Policy test",
                    identity="Houston-Policy-ID",
                    enable=False,  # Misconfigured
                    action="Allow",
                    quarantine_tag="DefaultFullAccessPolicy",
                    redirect=False,
                    redirect_address="",
                    is_built_in_protection=False,
                ),
            }
            defender_client.safe_attachments_rules = {
                "Houston Safe Attachments Policy test": SafeAttachmentsRule(
                    state="Enabled",
                    priority=0,
                    users=None,  # No users specified
                    groups=None,  # No groups specified
                    domains=None,  # No domains specified - applies to ALL users
                )
            }

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Custom policy should show "all users" in status_extended
            custom_result = next(
                r
                for r in result
                if r.resource_name == "Houston Safe Attachments Policy test"
            )
            assert custom_result.status == "FAIL"
            assert "is not properly configured" in custom_result.status_extended
            assert "all users" in custom_result.status_extended
            assert "priority 0" in custom_result.status_extended
