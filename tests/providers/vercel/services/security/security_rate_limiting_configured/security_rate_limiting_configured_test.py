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


class Test_security_rate_limiting_configured:
    def test_no_configs(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured import (
                security_rate_limiting_configured,
            )

            check = security_rate_limiting_configured()
            result = check.execute()
            assert len(result) == 0

    def test_rate_limiting_configured(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                rate_limiting_rules=[{"id": "rule1", "max_requests": 100}],
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
                "prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured import (
                security_rate_limiting_configured,
            )

            check = security_rate_limiting_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} ({PROJECT_ID}) has 1 rate limiting rule(s) configured."
            )
            assert result[0].team_id == TEAM_ID

    def test_no_rate_limiting(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                rate_limiting_rules=[],
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
                "prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_rate_limiting_configured.security_rate_limiting_configured import (
                security_rate_limiting_configured,
            )

            check = security_rate_limiting_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {PROJECT_NAME} ({PROJECT_ID}) does not have any rate limiting rules configured. This feature is only available on Vercel Pro/Enterprise plans."
            )
            assert result[0].team_id == TEAM_ID
