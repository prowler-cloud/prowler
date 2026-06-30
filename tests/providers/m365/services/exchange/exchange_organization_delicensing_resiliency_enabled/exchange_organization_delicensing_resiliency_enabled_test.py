from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

ORGANIZATION_KWARGS = dict(
    name="test-org",
    guid="org-guid",
    audit_disabled=False,
    oauth_enabled=True,
    mailtips_enabled=True,
    mailtips_external_recipient_enabled=False,
    mailtips_group_metrics_enabled=True,
    mailtips_large_audience_threshold=25,
)


class Test_exchange_organization_delicensing_resiliency_enabled:
    def test_no_organization(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_delicensing_resiliency_disabled_above_threshold(self):
        """Disabled + >= 5000 total licenses -> FAIL (fixer confirms eligibility)."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=False,
                total_paid_licenses=6000,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "preventive FAIL" in result[0].status_extended
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_delicensing_resiliency_disabled_at_threshold(self):
        """Disabled + exactly 5000 total licenses -> FAIL."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=False,
                total_paid_licenses=5000,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_delicensing_resiliency_disabled_below_threshold(self):
        """Disabled + < 5000 total licenses -> PASS (not applicable)."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=False,
                total_paid_licenses=4999,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not applicable" in result[0].status_extended
            assert "4999 total licenses" in result[0].status_extended

    def test_delicensing_resiliency_disabled_licenses_unknown(self):
        """Disabled + unknown license count -> FAIL."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=False,
                total_paid_licenses=None,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "preventive FAIL" in result[0].status_extended

    def test_delicensing_resiliency_enabled(self):
        """Enabled -> PASS regardless of license count."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=True,
                total_paid_licenses=6000,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is enabled" in result[0].status_extended
            assert result[0].resource == exchange_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_delicensing_resiliency_enabled_below_threshold(self):
        """Enabled + below threshold -> still PASS (enabled always wins)."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled import (
                exchange_organization_delicensing_resiliency_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                **ORGANIZATION_KWARGS,
                delayed_delicensing_enabled=True,
                total_paid_licenses=100,
            )

            check = exchange_organization_delicensing_resiliency_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is enabled" in result[0].status_extended
