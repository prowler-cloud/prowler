from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_nat_dnat_sensitive_ports:
    def test_dnat_sensitive_port_fails(self):
        nat_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports.nat_client",
                new=nat_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.nat.nat_service import (
                DnatRule,
            )
            from prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports import (
                nat_dnat_sensitive_ports,
            )

            nat_client.dnat_rules = [
                DnatRule(
                    id="dnat-001",
                    nat_gateway_id="nat-gw-001",
                    floating_ip_address="1.2.3.4",
                    external_service_port=22,
                    internal_service_port=22,
                    protocol="tcp",
                    region="la-south-2",
                ),
            ]
            nat_client.audited_account = "123456789012"

            check = nat_dnat_sensitive_ports()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert "22" in results[0].status_extended
            assert "SSH" in results[0].status_extended

    def test_dnat_non_sensitive_port_passes(self):
        nat_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports.nat_client",
                new=nat_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.nat.nat_service import (
                DnatRule,
            )
            from prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports import (
                nat_dnat_sensitive_ports,
            )

            nat_client.dnat_rules = [
                DnatRule(
                    id="dnat-002",
                    nat_gateway_id="nat-gw-001",
                    floating_ip_address="5.6.7.8",
                    external_service_port=8080,
                    internal_service_port=80,
                    protocol="tcp",
                    region="la-south-2",
                ),
            ]
            nat_client.audited_account = "123456789012"

            check = nat_dnat_sensitive_ports()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"

    def test_dnat_mixed_ports(self):
        nat_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports.nat_client",
                new=nat_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.nat.nat_service import (
                DnatRule,
            )
            from prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports import (
                nat_dnat_sensitive_ports,
            )

            nat_client.dnat_rules = [
                DnatRule(
                    id="dnat-003",
                    nat_gateway_id="nat-gw-001",
                    floating_ip_address="1.2.3.4",
                    external_service_port=3306,
                    internal_service_port=3306,
                    protocol="tcp",
                    region="la-south-2",
                ),
                DnatRule(
                    id="dnat-004",
                    nat_gateway_id="nat-gw-001",
                    floating_ip_address="5.6.7.8",
                    external_service_port=443,
                    internal_service_port=443,
                    protocol="tcp",
                    region="la-south-2",
                ),
            ]
            nat_client.audited_account = "123456789012"

            check = nat_dnat_sensitive_ports()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "FAIL"
            assert "MySQL" in results[0].status_extended
            assert results[1].status == "PASS"

    def test_dnat_no_rules(self):
        nat_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports.nat_client",
                new=nat_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.nat.nat_dnat_sensitive_ports.nat_dnat_sensitive_ports import (
                nat_dnat_sensitive_ports,
            )

            nat_client.dnat_rules = []
            nat_client.audited_account = "123456789012"

            check = nat_dnat_sensitive_ports()
            results = check.execute()

            assert len(results) == 0
