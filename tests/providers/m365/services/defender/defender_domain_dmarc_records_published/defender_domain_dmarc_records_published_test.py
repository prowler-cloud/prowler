from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_domain_dmarc_records_published:
    def test_no_domains(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.domain_dmarc_configurations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )

            check = defender_domain_dmarc_records_published()
            result = check.execute()
            assert len(result) == 0

    def test_domain_dmarc_reject(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain1"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@domain1",
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DMARC record is published on Exchange Online for domain with ID {domain_id} with enforcement policy p=reject."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_dmarc_quarantine(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain2"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record="v=DMARC1;p=quarantine;pct=100",
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DMARC record is published on Exchange Online for domain with ID {domain_id} with enforcement policy p=quarantine."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_dmarc_none_policy(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain3"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record="v=DMARC1; p=none",
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DMARC record is published on Exchange Online for domain with ID {domain_id} but uses monitoring-only policy p=none."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_dmarc_missing(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain4"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record=None,
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DMARC record is not published on Exchange Online for domain with ID {domain_id}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_dmarc_malformed(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain5"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record="this is not a dmarc record",
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DMARC record for domain with ID {domain_id} is malformed and does not include a valid enforcement policy."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"

    def test_domain_dmarc_no_policy_tag(self):
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
                "prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DomainDmarcConfiguration,
            )

            domain_id = "domain6"

            defender_client.domain_dmarc_configurations = {
                domain_id: DomainDmarcConfiguration(
                    domain=domain_id,
                    dmarc_record="v=DMARC1; rua=mailto:dmarc@domain6",
                )
            }

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DMARC record for domain with ID {domain_id} is malformed and does not include a valid enforcement policy."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == domain_id
            assert result[0].resource_id == domain_id
            assert result[0].location == "global"
