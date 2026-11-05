from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_strict_preset_security_policy_enabled:
    def test_defender_no_preset_policy_rules_data(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.eop_protection_policy_rules = None
        defender_client.atp_protection_policy_rules = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_eop_rules_unavailable(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = None
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_strict_preset_enabled_for_both(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                    recipient_domain_is=["contoso.com"],
                )
            ]
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                    recipient_domain_is=["contoso.com"],
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is enabled for both Exchange Online Protection and Defender for Office 365."
            )
            assert result[0].resource == {
                "eop": [
                    rule.dict() for rule in defender_client.eop_protection_policy_rules
                ],
                "atp": [
                    rule.dict() for rule in defender_client.atp_protection_policy_rules
                ],
            }
            assert result[0].resource_name == "Strict Preset Security Policy"
            assert result[0].resource_id == "strictPresetSecurityPolicy"
            assert result[0].location == "global"

    def test_defender_strict_preset_enabled_all_recipients(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            # Empty recipient conditions mean the rule applies to all recipients.
            defender_client.eop_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                )
            ]
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is enabled for both Exchange Online Protection and Defender for Office 365."
            )

    def test_defender_strict_preset_only_eop(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                )
            ]
            defender_client.atp_protection_policy_rules = []

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is not enabled for Defender for Office 365."
            )

    def test_defender_strict_preset_only_atp(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = []
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Enabled",
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is not enabled for Exchange Online Protection."
            )

    def test_defender_strict_preset_disabled_state(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Disabled",
                )
            ]
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Strict Preset Security Policy",
                    state="Disabled",
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is not enabled for Exchange Online Protection or Defender for Office 365."
            )

    def test_defender_standard_preset_only(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                PresetSecurityPolicyRule,
            )
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            defender_client.eop_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Standard Preset Security Policy",
                    state="Enabled",
                )
            ]
            defender_client.atp_protection_policy_rules = [
                PresetSecurityPolicyRule(
                    name="Standard Preset Security Policy",
                    state="Enabled",
                )
            ]

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is not enabled for Exchange Online Protection or Defender for Office 365."
            )

    def test_defender_no_preset_rules(self):
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
                "prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_strict_preset_security_policy_enabled.defender_strict_preset_security_policy_enabled import (
                defender_strict_preset_security_policy_enabled,
            )

            # Rules were collected successfully but the presets were never enabled.
            defender_client.eop_protection_policy_rules = []
            defender_client.atp_protection_policy_rules = []

            check = defender_strict_preset_security_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "The Strict Preset Security Policy is not enabled for Exchange Online Protection or Defender for Office 365."
            )
            assert result[0].resource == {"eop": [], "atp": []}
            assert result[0].resource_name == "Strict Preset Security Policy"
            assert result[0].resource_id == "strictPresetSecurityPolicy"
            assert result[0].location == "global"
