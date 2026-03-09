from unittest import mock

from prowler.providers.m365.services.defender.defender_service import (
    TeamsProtectionPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_zap_for_teams_enabled:
    def test_zap_enabled_pass(self):
        """Test PASS scenario when ZAP is enabled for Teams."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.teams_protection_policy = TeamsProtectionPolicy(
            identity="Teams Protection Policy",
            zap_enabled=True,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled import (
                defender_zap_for_teams_enabled,
            )

            check = defender_zap_for_teams_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Zero-hour auto purge (ZAP) is enabled for Microsoft Teams."
            )
            assert result[0].resource == defender_client.teams_protection_policy.dict()
            assert result[0].resource_name == "Teams Protection Policy"
            assert result[0].resource_id == "teamsProtectionPolicy"
            assert result[0].location == "global"

    def test_zap_disabled_fail(self):
        """Test FAIL scenario when ZAP is disabled for Teams."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.teams_protection_policy = TeamsProtectionPolicy(
            identity="Teams Protection Policy",
            zap_enabled=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled import (
                defender_zap_for_teams_enabled,
            )

            check = defender_zap_for_teams_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Zero-hour auto purge (ZAP) is not enabled for Microsoft Teams."
            )
            assert result[0].resource == defender_client.teams_protection_policy.dict()
            assert result[0].resource_name == "Teams Protection Policy"
            assert result[0].resource_id == "teamsProtectionPolicy"
            assert result[0].location == "global"

    def test_teams_protection_policy_none(self):
        """Test scenario when Teams protection policy is not available."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.teams_protection_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_zap_for_teams_enabled.defender_zap_for_teams_enabled import (
                defender_zap_for_teams_enabled,
            )

            check = defender_zap_for_teams_enabled()
            result = check.execute()

            assert len(result) == 0
