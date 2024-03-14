from unittest import mock

from prowler.providers.gcp.services.compute.compute_service import Address
from tests.providers.gcp.lib.audit_info_utils import GCP_PROJECT_ID


class Test_compute_public_address_shodan:
    def test_no_public_ip_addresses(self):
        compute_client = mock.MagicMock
        compute_client.addresses = {}
        compute_client.audit_info = mock.MagicMock

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Network",
            new=compute_client,
        ) as service_client, mock.patch(
            "prowler.providers.gcp.services.compute.compute_client.compute_client",
            new=service_client,
        ):
            from prowler.providers.gcp.services.compute.compute_public_address_shodan.compute_public_address_shodan import (
                compute_public_address_shodan,
            )

            compute_client.audit_config = {"shodan_api_key": "api_key"}

            check = compute_public_address_shodan()
            result = check.execute()
            assert len(result) == 0

    def test_compute_ip_in_shodan(self):
        compute_client = mock.MagicMock
        public_ip_id = "id"
        public_ip_name = "name"
        ip_address = "ip_address"
        shodan_info = {
            "ports": [80, 443],
            "isp": "Microsoft Corporation",
            "country_name": "country_name",
        }
        compute_client.audit_info = mock.MagicMock

        compute_client.addresses = [
            Address(
                id=public_ip_id,
                name=public_ip_name,
                type="EXTERNAL",
                ip=ip_address,
                region="region",
                network="network",
                project_id=GCP_PROJECT_ID,
            )
        ]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Network",
            new=compute_client,
        ) as service_client, mock.patch(
            "prowler.providers.gcp.services.compute.compute_client.compute_client",
            new=service_client,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_public_address_shodan.compute_public_address_shodan.shodan.Shodan.host",
            return_value=shodan_info,
        ):
            from prowler.providers.gcp.services.compute.compute_public_address_shodan.compute_public_address_shodan import (
                compute_public_address_shodan,
            )

            compute_client.audit_config = {"shodan_api_key": "api_key"}
            check = compute_public_address_shodan()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Public Address {ip_address} listed in Shodan with open ports {str(shodan_info['ports'])} and ISP {shodan_info['isp']} in {shodan_info['country_name']}. More info at https://www.shodan.io/host/{ip_address}."
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == "region"
            assert result[0].resource_id == public_ip_id
