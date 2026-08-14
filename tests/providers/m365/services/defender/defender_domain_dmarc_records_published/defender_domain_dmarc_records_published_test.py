from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_domain_dmarc_records_published:
    def test_dmarc_with_reject_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        mock_dns_answer = mock.MagicMock()
        mock_dns_answer.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        mock_dns_response = [mock_dns_answer]

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
            mock.patch(
                "dns.resolver.resolve",
                return_value=mock_dns_response,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "p=reject" in result[0].status_extended

    def test_dmarc_with_quarantine_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        mock_dns_answer = mock.MagicMock()
        mock_dns_answer.strings = [
            b"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
        ]
        mock_dns_response = [mock_dns_answer]

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
            mock.patch(
                "dns.resolver.resolve",
                return_value=mock_dns_response,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "p=quarantine" in result[0].status_extended

    def test_dmarc_with_none_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        mock_dns_answer = mock.MagicMock()
        mock_dns_answer.strings = [b"v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
        mock_dns_response = [mock_dns_answer]

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
            mock.patch(
                "dns.resolver.resolve",
                return_value=mock_dns_response,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "p=none" in result[0].status_extended

    def test_dmarc_not_found(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        import dns.resolver

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
            mock.patch(
                "dns.resolver.resolve",
                side_effect=dns.resolver.NoAnswer(),
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "No DMARC record found" in result[0].status_extended

    def test_dns_resolver_failure_marks_fail(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        import dns.resolver

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
            mock.patch(
                "dns.resolver.resolve",
                side_effect=dns.resolver.Timeout(),
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "DNS resolver error" in result[0].status_extended
            assert "manual review" in result[0].status_extended

    def test_malformed_dmarc_record(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        mock_dns_answer = mock.MagicMock()
        mock_dns_answer.strings = [b"not a valid dmarc record"]
        mock_dns_response = [mock_dns_answer]

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
            mock.patch(
                "dns.resolver.resolve",
                return_value=mock_dns_response,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="example.com")
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"
            assert "malformed" in result[0].status_extended

    def test_no_domains(self):
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

            defender_client.dkim_configurations = []

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 0

    def test_multiple_domains_mixed_results(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        import dns.resolver

        def dns_side_effect(domain, record_type):
            mock_answer = mock.MagicMock()
            if "good.com" in domain:
                mock_answer.strings = [b"v=DMARC1; p=reject"]
            elif "bad.com" in domain:
                mock_answer.strings = [b"v=DMARC1; p=none"]
            else:
                raise dns.resolver.NXDOMAIN()
            return [mock_answer]

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
            mock.patch(
                "dns.resolver.resolve",
                side_effect=dns_side_effect,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_domain_dmarc_records_published.defender_domain_dmarc_records_published import (
                defender_domain_dmarc_records_published,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DkimConfig,
            )

            defender_client.dkim_configurations = [
                DkimConfig(dkim_signing_enabled=True, id="good.com"),
                DkimConfig(dkim_signing_enabled=True, id="bad.com"),
                DkimConfig(dkim_signing_enabled=False, id="missing.com"),
            ]

            check = defender_domain_dmarc_records_published()
            result = check.execute()

            assert len(result) == 3
            assert result[0].status == "PASS"
            assert result[0].resource_id == "good.com"
            assert result[1].status == "FAIL"
            assert result[1].resource_id == "bad.com"
            assert result[2].status == "FAIL"
            assert result[2].resource_id == "missing.com"
