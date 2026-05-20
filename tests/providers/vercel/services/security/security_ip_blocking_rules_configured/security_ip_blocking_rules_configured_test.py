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


class Test_security_ip_blocking_rules_configured:
    def test_no_configs(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured import (
                security_ip_blocking_rules_configured,
            )

            check = security_ip_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 0

    def test_ip_rules_configured(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                ip_blocking_rules=[{"id": "rule1", "ip": "192.168.1.0/24"}],
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
                "prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured import (
                security_ip_blocking_rules_configured,
            )

            check = security_ip_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} ({PROJECT_ID}) has 1 IP blocking rule(s) configured."
            )
            assert result[0].team_id == TEAM_ID

    def test_no_ip_rules(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                ip_blocking_rules=[],
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
                "prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured import (
                security_ip_blocking_rules_configured,
            )

            check = security_ip_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} ({PROJECT_ID}) does not have any IP blocking rules configured."
            )
            assert result[0].team_id == TEAM_ID

    def test_ip_rules_status_unavailable_hobby_plan(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                billing_plan="hobby",
                firewall_config_accessible=False,
                managed_rulesets=None,
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
                "prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_ip_blocking_rules_configured.security_ip_blocking_rules_configured import (
                security_ip_blocking_rules_configured,
            )

            check = security_ip_blocking_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} ({PROJECT_ID}) could not be assessed for IP blocking rules because the firewall configuration endpoint was not accessible. Manual verification is required. This may be expected because IP blocking rules are not available on the Vercel Hobby plan."
            )
