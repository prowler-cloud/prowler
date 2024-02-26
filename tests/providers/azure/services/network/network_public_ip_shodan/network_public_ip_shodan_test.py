from unittest import mock

from prowler.providers.azure.services.network.network_service import PublicIp
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_network_public_ip_shodan:
    def test_no_public_ip_addresses(self):
        network_client = mock.MagicMock
        network_client.public_ip_addresses = {}
        network_client.audit_info = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_public_ip_shodan.network_public_ip_shodan import (
                network_public_ip_shodan,
            )

            network_client.audit_info.audit_config = {"shodan_api_key": "api_key"}

            check = network_public_ip_shodan()
            result = check.execute()
            assert len(result) == 0

    def test_network_ip_in_shodan(self):
        network_client = mock.MagicMock
        public_ip_id = "id"
        public_ip_name = "name"
        ip_address = "ip_address"
        shodan_info = {
            "ports": [80, 443],
            "isp": "Microsoft Corporation",
            "country_name": "country_name",
        }
        network_client.audit_info = mock.MagicMock

        network_client.public_ip_addresses = {
            AZURE_SUBSCRIPTION: [
                PublicIp(
                    id=public_ip_id,
                    name=public_ip_name,
                    location=None,
                    ip_address=ip_address,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ), mock.patch(
            "prowler.providers.azure.services.network.network_public_ip_shodan.network_public_ip_shodan.shodan.Shodan.host",
            return_value=shodan_info,
        ):
            from prowler.providers.azure.services.network.network_public_ip_shodan.network_public_ip_shodan import (
                network_public_ip_shodan,
            )

            network_client.audit_info.audit_config = {"shodan_api_key": "api_key"}
            check = network_public_ip_shodan()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Public IP {ip_address} listed in Shodan with open ports {str(shodan_info['ports'])} and ISP {shodan_info['isp']} in {shodan_info['country_name']}. More info at https://www.shodan.io/host/{ip_address}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == public_ip_name
            assert result[0].resource_id == public_ip_id
