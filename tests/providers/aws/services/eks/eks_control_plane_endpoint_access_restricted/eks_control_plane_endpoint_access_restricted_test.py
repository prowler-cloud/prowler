from re import search
from unittest import mock

from prowler.providers.aws.services.eks.eks_service import EKSCluster
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

cluster_name = "cluster_test"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)


class Test_eks_control_plane_endpoint_access_restricted:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_endpoint_access_restricted.eks_control_plane_endpoint_access_restricted import (
                eks_control_plane_endpoint_access_restricted,
            )

            check = eks_control_plane_endpoint_access_restricted()
            result = check.execute()
            assert len(result) == 0

    def test_control_plane_access_private(self):
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
                public_access_cidrs=["123.123.123.123/32"],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_endpoint_access_restricted.eks_control_plane_endpoint_access_restricted import (
                eks_control_plane_endpoint_access_restricted,
            )

            check = eks_control_plane_endpoint_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Cluster endpoint access is private for EKS cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_control_plane_access_restricted(self):
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
                public_access_cidrs=["123.123.123.123/32"],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_endpoint_access_restricted.eks_control_plane_endpoint_access_restricted import (
                eks_control_plane_endpoint_access_restricted,
            )

            check = eks_control_plane_endpoint_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Cluster control plane access is restricted for EKS cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_control_plane_public(self):
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
                public_access_cidrs=["123.123.123.123/32", "0.0.0.0/0"],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_endpoint_access_restricted.eks_control_plane_endpoint_access_restricted import (
                eks_control_plane_endpoint_access_restricted,
            )

            check = eks_control_plane_endpoint_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Cluster control plane access is not restricted for EKS cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_control_plane_public_and_private(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
                endpoint_public_access=True,
                endpoint_private_access=True,
                public_access_cidrs=["123.123.123.123/32", "0.0.0.0/0"],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_endpoint_access_restricted.eks_control_plane_endpoint_access_restricted import (
                eks_control_plane_endpoint_access_restricted,
            )

            check = eks_control_plane_endpoint_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Cluster control plane access is not restricted for EKS cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
