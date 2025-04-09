from unittest import mock

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_defender_domain_dkim_enabled:
    def test_dkim_enabled(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled import (
                defender_domain_dkim_enabled,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client = mock.MagicMock
            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="domain1")
            ]

            check = defender_domain_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "DKIM is enabled for domain with ID domain1."
            )
            assert result[0].resource == defender_client.dkim_configurations[0].dict()
            assert result[0].resource_name == "DKIM Configuration"
            assert result[0].resource_id == "domain1"
            assert result[0].location == "global"

    def test_dkim_disabled(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled import (
                defender_domain_dkim_enabled,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client = mock.MagicMock
            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=False, id="domain2")
            ]

            check = defender_domain_dkim_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DKIM is not enabled for domain with ID domain2."
            )
            assert result[0].resource == defender_client.dkim_configurations[0].dict()
            assert result[0].resource_name == "DKIM Configuration"
            assert result[0].resource_id == "domain2"
            assert result[0].location == "global"

    def test_no_dkim_configurations(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_domain_dkim_enabled.defender_domain_dkim_enabled import (
                defender_domain_dkim_enabled,
            )

            defender_client = mock.MagicMock
            defender_client.dkim_configurations = []

            check = defender_domain_dkim_enabled()
            result = check.execute()
            assert len(result) == 0
