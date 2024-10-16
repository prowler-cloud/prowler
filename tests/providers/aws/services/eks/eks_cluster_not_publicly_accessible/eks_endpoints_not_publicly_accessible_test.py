from unittest import mock

from prowler.providers.aws.services.eks.eks_service import EKSCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

cluster_name = "cluster_test"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)


class Test_eks_cluster_not_publicly_accessible:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_not_publicly_accessible.eks_cluster_not_publicly_accessible import (
                eks_cluster_not_publicly_accessible,
            )

            check = eks_cluster_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_cluster_public_access(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
                endpoint_public_access=True,
                endpoint_private_access=False,
                public_access_cidrs=["0.0.0.0/0"],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_not_publicly_accessible.eks_cluster_not_publicly_accessible import (
                eks_cluster_not_publicly_accessible,
            )

            check = eks_cluster_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"EKS cluster {cluster_name} is publicly accessible."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_endpoint_not_public_access(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
                endpoint_public_access=False,
                endpoint_private_access=True,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_not_publicly_accessible.eks_cluster_not_publicly_accessible import (
                eks_cluster_not_publicly_accessible,
            )

            check = eks_cluster_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"EKS cluster {cluster_name} is not publicly accessible."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
