from unittest import mock

from prowler.providers.aws.services.eks.eks_service import EKSCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

cluster_name = "cluster_test"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)

class Test_eks_cluster_ensure_version_is_supported:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_ensure_version_is_supported.eks_cluster_ensure_version_is_supported import (
                eks_cluster_ensure_version_is_supported,
            )

            check = eks_cluster_ensure_version_is_supported()
            result = check.execute()
            assert len(result) == 0
    
    def test_cluster_below_supported_verison(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="0.28.9",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_ensure_version_is_supported.eks_cluster_ensure_version_is_supported import (
                eks_cluster_ensure_version_is_supported,
            )

            check = eks_cluster_ensure_version_is_supported()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} must have a version of 1.28 or greater."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
    
    def test_cluster_below_supported_verison2(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="1.27.9",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_ensure_version_is_supported.eks_cluster_ensure_version_is_supported import (
                eks_cluster_ensure_version_is_supported,
            )

            check = eks_cluster_ensure_version_is_supported()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} must have a version of 1.28 or greater."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
    
    def test_cluster_above_supported_verison(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="2.27.9",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_ensure_version_is_supported.eks_cluster_ensure_version_is_supported import (
                eks_cluster_ensure_version_is_supported,
            )

            check = eks_cluster_ensure_version_is_supported()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} version is supported."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
        
    def test_cluster_above_supported_verison2(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="2.00",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_ensure_version_is_supported.eks_cluster_ensure_version_is_supported import (
                eks_cluster_ensure_version_is_supported,
            )

            check = eks_cluster_ensure_version_is_supported()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} version is supported."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1