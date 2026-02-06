from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_safe_attachments_policy_enabled:
    def test_no_safe_attachments_policies(self):
        """Test FAIL when there are no Safe Attachments policies configured."""
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

            defender_client.safe_attachments_policies = []

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No Safe Attachments policies found" in result[0].status_extended
            assert result[0].resource_name == "Safe Attachments"
            assert result[0].resource_id == "safe_attachments_policies"

    def test_builtin_protection_policy_properly_configured(self):
        """Test PASS when Built-In Protection Policy has Enable=True, Action=Block, QuarantineTag=AdminOnlyAccessPolicy."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Safe Attachments Built-In Protection Policy is properly configured with Enable=True, Action=Block, and QuarantineTag=AdminOnlyAccessPolicy."
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In Protection Policy"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_builtin_protection_policy_enable_false(self):
        """Test FAIL when Built-In Protection Policy has Enable=False."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=False,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments Built-In Protection Policy is not properly configured: Enable is not True."
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In Protection Policy"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_builtin_protection_policy_wrong_action(self):
        """Test FAIL when Built-In Protection Policy has Action other than Block."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=True,
                    action="Allow",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments Built-In Protection Policy is not properly configured: Action is Allow, not Block."
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In Protection Policy"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_builtin_protection_policy_wrong_quarantine_tag(self):
        """Test FAIL when Built-In Protection Policy has incorrect QuarantineTag."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=True,
                    action="Block",
                    quarantine_tag="DefaultFullAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments Built-In Protection Policy is not properly configured: QuarantineTag is DefaultFullAccessPolicy, not AdminOnlyAccessPolicy."
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In Protection Policy"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_builtin_protection_policy_multiple_misconfigurations(self):
        """Test FAIL when Built-In Protection Policy has multiple misconfigurations."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=False,
                    action="Allow",
                    quarantine_tag="DefaultFullAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Enable is not True" in result[0].status_extended
            assert "Action is Allow, not Block" in result[0].status_extended
            assert (
                "QuarantineTag is DefaultFullAccessPolicy, not AdminOnlyAccessPolicy"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Built-In Protection Policy"
            assert result[0].resource_id == "Built-In Protection Policy"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_custom_policy_enabled_with_block_action(self):
        """Test PASS for custom policy with Enable=True and Action=Block."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Custom Safe Attachments Policy",
                    identity="custom-safe-attachments-policy-id",
                    enable=True,
                    action="Block",
                    quarantine_tag="DefaultFullAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Safe Attachments policy Custom Safe Attachments Policy is enabled with Action=Block."
            )
            assert result[0].resource_name == "Custom Safe Attachments Policy"
            assert result[0].resource_id == "custom-safe-attachments-policy-id"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_custom_policy_not_enabled(self):
        """Test FAIL for custom policy that is not enabled."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Custom Safe Attachments Policy",
                    identity="custom-safe-attachments-policy-id",
                    enable=False,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments policy Custom Safe Attachments Policy is not enabled."
            )
            assert result[0].resource_name == "Custom Safe Attachments Policy"
            assert result[0].resource_id == "custom-safe-attachments-policy-id"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_custom_policy_enabled_with_non_block_action(self):
        """Test FAIL for custom policy with Enable=True but Action other than Block."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Custom Safe Attachments Policy",
                    identity="custom-safe-attachments-policy-id",
                    enable=True,
                    action="Replace",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments policy Custom Safe Attachments Policy has Action=Replace, which is less secure than Block."
            )
            assert result[0].resource_name == "Custom Safe Attachments Policy"
            assert result[0].resource_id == "custom-safe-attachments-policy-id"
            assert result[0].resource == defender_client.safe_attachments_policies[0]

    def test_multiple_policies_mixed_results(self):
        """Test multiple policies with different configurations returning mixed results."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Built-In Protection Policy",
                    identity="Built-In Protection Policy",
                    enable=True,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                ),
                SafeAttachmentsPolicy(
                    name="Custom Policy 1",
                    identity="custom-policy-1",
                    enable=True,
                    action="Block",
                    quarantine_tag="DefaultFullAccessPolicy",
                    redirect=False,
                    redirect_address="",
                ),
                SafeAttachmentsPolicy(
                    name="Custom Policy 2",
                    identity="custom-policy-2",
                    enable=False,
                    action="Block",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=False,
                    redirect_address="",
                ),
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 3

            # Built-In Protection Policy - PASS
            assert result[0].status == "PASS"
            assert result[0].resource_name == "Built-In Protection Policy"
            assert (
                result[0].status_extended
                == "Safe Attachments Built-In Protection Policy is properly configured with Enable=True, Action=Block, and QuarantineTag=AdminOnlyAccessPolicy."
            )

            # Custom Policy 1 - PASS (enabled with Block action)
            assert result[1].status == "PASS"
            assert result[1].resource_name == "Custom Policy 1"
            assert (
                result[1].status_extended
                == "Safe Attachments policy Custom Policy 1 is enabled with Action=Block."
            )

            # Custom Policy 2 - FAIL (not enabled)
            assert result[2].status == "FAIL"
            assert result[2].resource_name == "Custom Policy 2"
            assert (
                result[2].status_extended
                == "Safe Attachments policy Custom Policy 2 is not enabled."
            )

    def test_custom_policy_with_dynamic_delivery_action(self):
        """Test FAIL for custom policy with Action=DynamicDelivery which is less secure than Block."""
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

            defender_client.safe_attachments_policies = [
                SafeAttachmentsPolicy(
                    name="Dynamic Delivery Policy",
                    identity="dynamic-delivery-policy-id",
                    enable=True,
                    action="DynamicDelivery",
                    quarantine_tag="AdminOnlyAccessPolicy",
                    redirect=True,
                    redirect_address="security@example.com",
                )
            ]

            check = defender_safe_attachments_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe Attachments policy Dynamic Delivery Policy has Action=DynamicDelivery, which is less secure than Block."
            )
            assert result[0].resource_name == "Dynamic Delivery Policy"
            assert result[0].resource_id == "dynamic-delivery-policy-id"
            assert result[0].resource == defender_client.safe_attachments_policies[0]
