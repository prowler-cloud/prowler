from re import search
from unittest import mock

from prowler.providers.gcp.services.dns.dns_service import Policy

GCP_PROJECT_ID = "123456789012"


class Test_compute_network_dns_logging_enabled:
    def test_compute_no_networks(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = []
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled import (
                compute_network_dns_logging_enabled,
            )

            check = compute_network_dns_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_network(self):
        from prowler.providers.gcp.services.compute.compute_service import Network

        network = Network(
            name="test", id="test_id", project_id=GCP_PROJECT_ID, subnet_mode="auto"
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = [network]
        compute_client.region = "global"

        policy = Policy(
            name="test",
            id="test_id",
            logging=True,
            networks=["test"],
            project_id=GCP_PROJECT_ID,
        )

        dns_client = mock.MagicMock
        dns_client.project_ids = [GCP_PROJECT_ID]
        dns_client.policies = [policy]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled.compute_client",
            new=compute_client,
        ):
            with mock.patch(
                "prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled.dns_client",
                new=dns_client,
            ):
                from prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled import (
                    compute_network_dns_logging_enabled,
                )

                check = compute_network_dns_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has DNS logging enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == network.id
                assert result[0].resource_name == network.name
                assert result[0].project_id == GCP_PROJECT_ID
                assert result[0].location == compute_client.region

    def test_one_uncompliant_network(self):
        from prowler.providers.gcp.services.compute.compute_service import Network

        network = Network(
            name="test", id="test_id", project_id=GCP_PROJECT_ID, subnet_mode="auto"
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.networks = [network]
        compute_client.region = "global"

        policy = Policy(
            name="test",
            id="test_id",
            logging=False,
            networks=["test"],
            project_id=GCP_PROJECT_ID,
        )

        dns_client = mock.MagicMock
        dns_client.project_ids = [GCP_PROJECT_ID]
        dns_client.policies = [policy]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled.compute_client",
            new=compute_client,
        ):
            with mock.patch(
                "prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled.dns_client",
                new=dns_client,
            ):
                from prowler.providers.gcp.services.compute.compute_network_dns_logging_enabled.compute_network_dns_logging_enabled import (
                    compute_network_dns_logging_enabled,
                )

                check = compute_network_dns_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "does not have DNS logging enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == network.id
                assert result[0].resource_name == network.name
                assert result[0].project_id == GCP_PROJECT_ID
                assert result[0].location == compute_client.region
