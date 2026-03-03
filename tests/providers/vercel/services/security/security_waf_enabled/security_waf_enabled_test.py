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


class Test_security_waf_enabled:
    def test_no_configs(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled import (
                security_waf_enabled,
            )

            check = security_waf_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_waf_enabled(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                firewall_enabled=True,
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
                "prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled import (
                security_waf_enabled,
            )

            check = security_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "PASS"
            assert "Web Application Firewall enabled" in result[0].status_extended

    def test_waf_disabled(self):
        security_client = mock.MagicMock
        security_client.firewall_configs = {
            PROJECT_ID: VercelFirewallConfig(
                project_id=PROJECT_ID,
                project_name=PROJECT_NAME,
                team_id=TEAM_ID,
                firewall_enabled=False,
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
                "prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled.security_client",
                new=security_client,
            ),
        ):
            from prowler.providers.vercel.services.security.security_waf_enabled.security_waf_enabled import (
                security_waf_enabled,
            )

            check = security_waf_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == PROJECT_NAME
            assert result[0].status == "FAIL"
            assert (
                "does not have the Web Application Firewall enabled"
                in result[0].status_extended
            )
