from re import search
from unittest import mock

from tests.providers.gcp.lib.audit_info_utils import GCP_PROJECT_ID


class Test_compute_subnet_flow_logs_enabled:
    def test_compute_no_subnets(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.subnets = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled import (
                compute_subnet_flow_logs_enabled,
            )

            check = compute_subnet_flow_logs_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_subnet(self):
        from prowler.providers.gcp.services.compute.compute_service import Subnet

        subnet = Subnet(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            flow_logs=True,
            network="network",
            region="global",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.subnets = [subnet]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled import (
                compute_subnet_flow_logs_enabled,
            )

            check = compute_subnet_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has flow logs enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == subnet.id
            assert result[0].resource_name == subnet.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == subnet.region

    def test_one_uncompliant_subnet(self):
        from prowler.providers.gcp.services.compute.compute_service import Subnet

        subnet = Subnet(
            name="test",
            id="test_id",
            project_id=GCP_PROJECT_ID,
            flow_logs=False,
            network="network",
            region="global",
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.subnets = [subnet]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_subnet_flow_logs_enabled.compute_subnet_flow_logs_enabled import (
                compute_subnet_flow_logs_enabled,
            )

            check = compute_subnet_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have flow logs enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == subnet.id
            assert result[0].resource_name == subnet.name
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == subnet.region
