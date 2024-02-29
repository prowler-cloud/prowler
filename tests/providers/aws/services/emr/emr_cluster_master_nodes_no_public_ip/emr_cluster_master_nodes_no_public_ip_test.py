from unittest import mock

from prowler.providers.aws.services.emr.emr_service import Cluster, ClusterStatus
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


class Test_emr_cluster_master_nodes_no_public_ip:
    def test_no_clusters(self):
        emr_client = mock.MagicMock
        emr_client.clusters = {}
        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import (
                emr_cluster_master_nodes_no_public_ip,
            )

            check = emr_cluster_master_nodes_no_public_ip()
            result = check.execute()

            assert len(result) == 0

    def test_cluster_public_running(self):
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import (
                emr_cluster_master_nodes_no_public_ip,
            )

            check = emr_cluster_master_nodes_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} has a Public IP."
            )

    def test_cluster_private_running(self):
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="compute.internal",
                public=False,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import (
                emr_cluster_master_nodes_no_public_ip,
            )

            check = emr_cluster_master_nodes_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} does not have a Public IP."
            )

    def test_cluster_public_terminated(self):
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.TERMINATED,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import (
                emr_cluster_master_nodes_no_public_ip,
            )

            check = emr_cluster_master_nodes_no_public_ip()
            result = check.execute()

            assert len(result) == 0

    def test_cluster_private_bootstrapping(self):
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.BOOTSTRAPPING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="compute.internal",
                public=False,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import (
                emr_cluster_master_nodes_no_public_ip,
            )

            check = emr_cluster_master_nodes_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} does not have a Public IP."
            )
