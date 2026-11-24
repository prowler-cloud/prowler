from unittest import mock

import pytest

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

    @pytest.mark.parametrize(
        (
            "endpoint_private_access",
            "public_access_cidrs",
            "expected_status",
            "expected_message",
        ),
        [
            pytest.param(
                False,
                ["0.0.0.0/0"],
                "FAIL",
                "is publicly accessible from 0.0.0.0/0.",
                id="unrestricted-ipv4",
            ),
            pytest.param(
                True,
                ["203.0.113.5/32", "::/0"],
                "FAIL",
                "is publicly accessible from ::/0.",
                id="unrestricted-ipv6",
            ),
            pytest.param(
                True,
                ["0.0.0.0/0", "::/0"],
                "FAIL",
                "is publicly accessible from 0.0.0.0/0, ::/0.",
                id="unrestricted-dual-stack",
            ),
            pytest.param(
                True,
                ["203.0.113.5/32", "2001:db8::/48"],
                "PASS",
                "has no unrestricted CIDR in its public access list.",
                id="restricted-dual-stack",
            ),
        ],
    )
    def test_cluster_public_access(
        self,
        endpoint_private_access,
        public_access_cidrs,
        expected_status,
        expected_message,
    ):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
                endpoint_public_access=True,
                endpoint_private_access=endpoint_private_access,
                public_access_cidrs=public_access_cidrs,
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
            assert result[0].status == expected_status
            assert result[0].status_extended == (
                f"EKS cluster {cluster_name} {expected_message}"
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    @pytest.mark.parametrize(
        "public_access_cidrs", [[], ["::/0"]], ids=["no-cidrs", "ipv6-cidr"]
    )
    def test_endpoint_not_public_access(self, public_access_cidrs):
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
                public_access_cidrs=public_access_cidrs,
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
