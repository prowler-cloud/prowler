from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_safelinks_policy_enabled:
    """Tests for the defender_safelinks_policy_enabled check."""

    def test_no_safe_links_policies(self):
        """Test when no Safe Links policies exist."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )

            defender_client.safe_links_policies = {}
            defender_client.safe_links_rules = {}

            check = defender_safelinks_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_builtin_policy_properly_configured(self):
        """Test when the built-in Safe Links policy is properly configured (PASS)."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=True,
                    is_default=False,
                )
            }
            defender_client.safe_links_rules = {}

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Safe Links policy Built-In Protection Policy is properly configured with all recommended settings."
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In-Protection-Policy-ID"

    def test_builtin_policy_misconfigured(self):
        """Test when the built-in Safe Links policy is misconfigured (FAIL)."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=False,
                    enable_safe_links_for_teams=False,
                    enable_safe_links_for_office=False,
                    track_clicks=False,
                    allow_click_through=True,
                    scan_urls=False,
                    enable_for_internal_senders=False,
                    deliver_message_after_scan=False,
                    disable_url_rewrite=True,
                    is_built_in_protection=True,
                    is_default=False,
                )
            }
            defender_client.safe_links_rules = {}

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Safe Links policy Built-In Protection Policy has the following misconfigured settings:"
                in result[0].status_extended
            )
            assert "EnableSafeLinksForEmail should be True" in result[0].status_extended
            assert "EnableSafeLinksForTeams should be True" in result[0].status_extended
            assert (
                "EnableSafeLinksForOffice should be True" in result[0].status_extended
            )
            assert "TrackClicks should be True" in result[0].status_extended
            assert "AllowClickThrough should be False" in result[0].status_extended
            assert "ScanUrls should be True" in result[0].status_extended
            assert (
                "EnableForInternalSenders should be True" in result[0].status_extended
            )
            assert "DeliverMessageAfterScan should be True" in result[0].status_extended
            assert "DisableUrlRewrite should be False" in result[0].status_extended
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In-Protection-Policy-ID"

    def test_multiple_policies_all_properly_configured(self):
        """Test when both built-in and custom policies are properly configured (PASS)."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=True,
                    is_default=False,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            defender_client.safe_links_rules = {
                "Custom Policy": SafeLinksRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=["Engineering"],
                    domains=["example.com"],
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the built-in policy result
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "PASS"
            assert (
                "Built-in Safe Links policy Built-In Protection Policy is properly configured"
                in builtin_result.status_extended
            )

            # Find the custom policy result
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "PASS"
            assert (
                "Custom Safe Links policy Custom Policy is properly configured"
                in custom_result.status_extended
            )
            assert "users: user@example.com" in custom_result.status_extended
            assert "groups: Engineering" in custom_result.status_extended
            assert "domains: example.com" in custom_result.status_extended
            assert "priority 0" in custom_result.status_extended

    def test_multiple_policies_builtin_ok_custom_misconfigured(self):
        """Test when built-in policy is ok but custom policy is misconfigured."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=True,
                    is_default=False,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=False,
                    enable_safe_links_for_teams=False,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=True,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            defender_client.safe_links_rules = {
                "Custom Policy": SafeLinksRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the built-in policy result
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "PASS"

            # Find the custom policy result
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "FAIL"
            assert (
                "Custom Safe Links policy Custom Policy has the following misconfigured settings:"
                in custom_result.status_extended
            )
            assert (
                "EnableSafeLinksForEmail should be True"
                in custom_result.status_extended
            )
            assert (
                "EnableSafeLinksForTeams should be True"
                in custom_result.status_extended
            )
            assert "AllowClickThrough should be False" in custom_result.status_extended
            assert (
                "the built-in policy is properly configured"
                in custom_result.status_extended.lower()
            )

    def test_multiple_policies_builtin_misconfigured_custom_ok(self):
        """Test when built-in policy is misconfigured but custom policy is ok."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=False,
                    enable_safe_links_for_teams=False,
                    enable_safe_links_for_office=False,
                    track_clicks=False,
                    allow_click_through=True,
                    scan_urls=False,
                    enable_for_internal_senders=False,
                    deliver_message_after_scan=False,
                    disable_url_rewrite=True,
                    is_built_in_protection=True,
                    is_default=False,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            defender_client.safe_links_rules = {
                "Custom Policy": SafeLinksRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=["Engineering"],
                    domains=["example.com"],
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the built-in policy result
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "FAIL"
            assert (
                "Built-in Safe Links policy Built-In Protection Policy has the following misconfigured settings:"
                in builtin_result.status_extended
            )

            # Find the custom policy result
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "PASS"
            assert (
                "Custom Safe Links policy Custom Policy is properly configured"
                in custom_result.status_extended
            )
            assert (
                "the built-in policy is not properly configured"
                in custom_result.status_extended.lower()
            )

    def test_multiple_policies_all_misconfigured(self):
        """Test when both built-in and custom policies are misconfigured (FAIL)."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=False,
                    enable_safe_links_for_teams=False,
                    enable_safe_links_for_office=False,
                    track_clicks=False,
                    allow_click_through=True,
                    scan_urls=False,
                    enable_for_internal_senders=False,
                    deliver_message_after_scan=False,
                    disable_url_rewrite=True,
                    is_built_in_protection=True,
                    is_default=False,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=False,
                    enable_safe_links_for_teams=False,
                    enable_safe_links_for_office=False,
                    track_clicks=False,
                    allow_click_through=True,
                    scan_urls=False,
                    enable_for_internal_senders=False,
                    deliver_message_after_scan=False,
                    disable_url_rewrite=True,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            defender_client.safe_links_rules = {
                "Custom Policy": SafeLinksRule(
                    state="Enabled",
                    priority=1,
                    users=None,
                    groups=None,
                    domains=["example.com"],
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the built-in policy result
            builtin_result = next(
                r for r in result if r.resource_name == "Built-In Protection Policy"
            )
            assert builtin_result.status == "FAIL"
            assert (
                "Built-in Safe Links policy Built-In Protection Policy has the following misconfigured settings:"
                in builtin_result.status_extended
            )

            # Find the custom policy result
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "FAIL"
            assert (
                "Custom Safe Links policy Custom Policy has the following misconfigured settings:"
                in custom_result.status_extended
            )
            assert (
                "the built-in policy is also not properly configured"
                in custom_result.status_extended.lower()
            )

    def test_default_policy_properly_configured(self):
        """Test when a default Safe Links policy (is_default=True) is properly configured."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Default Policy": SafeLinksPolicy(
                    name="Default Policy",
                    identity="Default-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=True,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            defender_client.safe_links_rules = {
                "Custom Policy": SafeLinksRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the default policy result
            default_result = next(
                r for r in result if r.resource_name == "Default Policy"
            )
            assert default_result.status == "PASS"
            assert (
                "Built-in Safe Links policy Default Policy is properly configured"
                in default_result.status_extended
            )

    def test_custom_policy_without_rule(self):
        """Test when a custom policy has no associated rule."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
                SafeLinksRule,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=True,
                    is_default=False,
                ),
                "Custom Policy": SafeLinksPolicy(
                    name="Custom Policy",
                    identity="Custom-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=False,
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=False,
                    is_default=False,
                ),
            }
            # Custom policy has a rule but with a different name (no matching rule)
            defender_client.safe_links_rules = {
                "Other Policy": SafeLinksRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=None,
                    domains=None,
                )
            }

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 2

            # Find the custom policy result
            custom_result = next(
                r for r in result if r.resource_name == "Custom Policy"
            )
            assert custom_result.status == "PASS"
            assert "unknown scope" in custom_result.status_extended
            assert "priority unknown" in custom_result.status_extended

    def test_single_setting_misconfigured(self):
        """Test when only one setting is misconfigured."""
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
                "prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_safelinks_policy_enabled.defender_safelinks_policy_enabled import (
                defender_safelinks_policy_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                SafeLinksPolicy,
            )

            defender_client.safe_links_policies = {
                "Built-In Protection Policy": SafeLinksPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In-Protection-Policy-ID",
                    enable_safe_links_for_email=True,
                    enable_safe_links_for_teams=True,
                    enable_safe_links_for_office=True,
                    track_clicks=True,
                    allow_click_through=True,  # Only this is misconfigured
                    scan_urls=True,
                    enable_for_internal_senders=True,
                    deliver_message_after_scan=True,
                    disable_url_rewrite=False,
                    is_built_in_protection=True,
                    is_default=False,
                )
            }
            defender_client.safe_links_rules = {}

            check = defender_safelinks_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "AllowClickThrough should be False" in result[0].status_extended
            # Make sure other settings are NOT in the misconfigured list
            assert (
                "EnableSafeLinksForEmail should be True"
                not in result[0].status_extended
            )
            assert (
                "EnableSafeLinksForTeams should be True"
                not in result[0].status_extended
            )
