from unittest import mock

from prowler.providers.vercel.services.security.security_service import (
    VercelFirewallConfig,
)
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_security_custom_rules_configured:
    def test_no_configs(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured import (
                security_custom_rules_configured,
            )

            check = security_custom_rules_configured()
            result = check.execute()
            assert len(result) == 0

    def test_custom_rules_configured(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                custom_rules=[{"id": "rule1", "name": "Block bots"}],
                id=PROJECT_ID,
                name=PROJECT_NAME,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured import (
                security_custom_rules_configured,
            )

            check = security_custom_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert "custom firewall rule(s) configured" in result[0].status_extended

    def test_no_custom_rules(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                custom_rules=[],
                id=PROJECT_ID,
                name=PROJECT_NAME,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_custom_rules_configured.security_custom_rules_configured import (
                security_custom_rules_configured,
            )

            check = security_custom_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                "does not have any custom firewall rules" in result[0].status_extended
            )
