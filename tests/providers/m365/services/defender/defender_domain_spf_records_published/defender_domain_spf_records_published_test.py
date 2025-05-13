from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_domain_spf_records_published:
    def test_no_domains(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.domain_service_configurations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published import (
                defender_domain_spf_records_published,
            )

            check = defender_domain_spf_records_published()
            result = check.execute()
            assert len(result) == 0

    def test_domain_spf_record_present(self):
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
                "prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published import (
                defender_domain_spf_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainServiceConfiguration,
            )

            domain_id = "domain1"

            record = mock.MagicMock()
            record.record_type = "Txt"
            record.text = "v=spf1 include:spf.protection.outlook.com -all"

            defender_client.domain_service_configurations = {
                domain_id: DomainServiceConfiguration(
                    service_configuration_records=[record]
                )
            }

            check = defender_domain_spf_records_published()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SPF record is published on Exchange Online for domain with ID {domain_id}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_spf_record_missing(self):
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
                "prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_spf_records_published.defender_domain_spf_records_published import (
                defender_domain_spf_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainServiceConfiguration,
            )

            domain_id = "domain2"

            record = mock.MagicMock()
            record.record_type = "Txt"
            record.text = ""

            defender_client.domain_service_configurations = {
                domain_id: DomainServiceConfiguration(
                    service_configuration_records=[record]
                )
            }

            check = defender_domain_spf_records_published()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SPF record is not published on Exchange Online for domain with ID {domain_id}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"
