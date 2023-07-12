from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_compute_network_not_legacy:
    def test_compute_no_networks(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = []
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy import (
                compute_network_not_legacy,
            )

            check = compute_network_not_legacy()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_network(self):
        from prowler.providers.gcp.services.compute.compute_service import Network

        network = Network(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            subnet_mode="custom",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = [network]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy import (
                compute_network_not_legacy,
            )

            check = compute_network_not_legacy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Network test is not legacy",
                result[0].status_extended,
            )
            assert result[0].resource_id == network.id
            assert result[0].resource_name == network.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == compute_client.region

    def test_one_legacy_network(self):
        from prowler.providers.gcp.services.compute.compute_service import Network

        network = Network(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            subnet_mode="legacy",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = [network]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_not_legacy.compute_network_not_legacy import (
                compute_network_not_legacy,
            )

            check = compute_network_not_legacy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Legacy network test exists",
                result[0].status_extended,
            )
            assert result[0].resource_id == network.id
            assert result[0].resource_name == network.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == compute_client.region
