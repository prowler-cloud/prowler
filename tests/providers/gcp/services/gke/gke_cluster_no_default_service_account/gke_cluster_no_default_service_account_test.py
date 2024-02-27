from unittest import mock

from prowler.providers.gcp.services.gke.gke_service import Cluster, NodePool
from tests.providers.gcp.lib.audit_info_utils import GCP_PROJECT_ID


class Test_gke_cluster_no_default_service_account:
    def test_gke_no_clusters(self):
        gke_client = mock.MagicMock
        gke_client.clusters = {}

        with mock.patch(
            "prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account.gke_client",
            new=gke_client,
        ):
            from prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account import (
                gke_cluster_no_default_service_account,
            )

            check = gke_cluster_no_default_service_account()
            result = check.execute()
            assert len(result) == 0

    def test_one_cluster_without_node_pool(self):

        clusters = {
            "123": Cluster(
                name="test",
                id="123",
                location="eu-west-1",
                service_account="default",
                node_pools=[],
                project_id=GCP_PROJECT_ID,
            )
        }

        gke_client = mock.MagicMock
        gke_client.project_ids = [GCP_PROJECT_ID]
        gke_client.clusters = clusters
        gke_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account.gke_client",
            new=gke_client,
        ):
            from prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account import (
                gke_cluster_no_default_service_account,
            )

            check = gke_cluster_no_default_service_account()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GKE cluster {clusters['123'].name} is using the Compute Engine default service account."
            )
            assert result[0].project_id == clusters["123"].project_id
            assert result[0].resource_id == clusters["123"].id
            assert result[0].resource_name == clusters["123"].name
            assert result[0].location == clusters["123"].location

    def test_one_cluster_without_node_pool_without_default_sa(self):

        clusters = {
            "123": Cluster(
                name="test",
                id="123",
                location="eu-west-1",
                service_account="1231231231",
                node_pools=[],
                project_id=GCP_PROJECT_ID,
            )
        }

        gke_client = mock.MagicMock
        gke_client.project_ids = [GCP_PROJECT_ID]
        gke_client.clusters = clusters
        gke_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account.gke_client",
            new=gke_client,
        ):
            from prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account import (
                gke_cluster_no_default_service_account,
            )

            check = gke_cluster_no_default_service_account()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GKE cluster {clusters['123'].name} is not using the Compute Engine default service account."
            )
            assert result[0].project_id == clusters["123"].project_id
            assert result[0].resource_id == clusters["123"].id
            assert result[0].resource_name == clusters["123"].name
            assert result[0].location == clusters["123"].location

    def test_one_cluster_with_node_pool_with_default_sa(self):

        clusters = {
            "123": Cluster(
                name="test",
                id="123",
                location="eu-west-1",
                service_account="default",
                node_pools=[
                    NodePool(
                        name="test",
                        locations=["eu-west-1"],
                        service_account="default",
                        project_id=GCP_PROJECT_ID,
                    )
                ],
                project_id=GCP_PROJECT_ID,
            )
        }

        gke_client = mock.MagicMock
        gke_client.project_ids = [GCP_PROJECT_ID]
        gke_client.clusters = clusters
        gke_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account.gke_client",
            new=gke_client,
        ):
            from prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account import (
                gke_cluster_no_default_service_account,
            )

            check = gke_cluster_no_default_service_account()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GKE cluster {clusters['123'].name} is using the Compute Engine default service account."
            )
            assert result[0].project_id == clusters["123"].project_id
            assert result[0].resource_id == clusters["123"].id
            assert result[0].resource_name == clusters["123"].name
            assert result[0].location == clusters["123"].location

    def test_one_cluster_with_node_pool_with_non_default_sa(self):

        clusters = {
            "123": Cluster(
                name="test",
                id="123",
                location="eu-west-1",
                service_account="default",
                node_pools=[
                    NodePool(
                        name="test",
                        locations=["eu-west-1"],
                        service_account="123123123",
                        project_id=GCP_PROJECT_ID,
                    )
                ],
                project_id=GCP_PROJECT_ID,
            )
        }

        gke_client = mock.MagicMock
        gke_client.project_ids = [GCP_PROJECT_ID]
        gke_client.clusters = clusters
        gke_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account.gke_client",
            new=gke_client,
        ):
            from prowler.providers.gcp.services.gke.gke_cluster_no_default_service_account.gke_cluster_no_default_service_account import (
                gke_cluster_no_default_service_account,
            )

            check = gke_cluster_no_default_service_account()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GKE cluster {clusters['123'].name} is not using the Compute Engine default service account."
            )
            assert result[0].project_id == clusters["123"].project_id
            assert result[0].resource_id == clusters["123"].id
            assert result[0].resource_name == clusters["123"].name
            assert result[0].location == clusters["123"].location
