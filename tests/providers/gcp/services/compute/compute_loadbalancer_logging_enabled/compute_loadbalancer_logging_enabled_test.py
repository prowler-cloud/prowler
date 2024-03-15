from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_loadbalancer_logging_enabled:
    def test_compute_no_load_balancers(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.load_balancers = []

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled import (
                compute_loadbalancer_logging_enabled,
            )

            check = compute_loadbalancer_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_load_balancer(self):
        from prowler.providers.gcp.services.compute.compute_service import LoadBalancer

        load_balancer = LoadBalancer(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            logging=True,
            service="test",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.load_balancers = [load_balancer]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled import (
                compute_loadbalancer_logging_enabled,
            )

            check = compute_loadbalancer_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has logging enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == load_balancer.id
            assert result[0].resource_name == load_balancer.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == compute_client.region

    def test_one_uncompliant_load_balancer(self):
        from prowler.providers.gcp.services.compute.compute_service import LoadBalancer

        load_balancer = LoadBalancer(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            logging=False,
            service="test",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.load_balancers = [load_balancer]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_loadbalancer_logging_enabled.compute_loadbalancer_logging_enabled import (
                compute_loadbalancer_logging_enabled,
            )

            check = compute_loadbalancer_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have logging enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == load_balancer.id
            assert result[0].resource_name == load_balancer.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == compute_client.region
