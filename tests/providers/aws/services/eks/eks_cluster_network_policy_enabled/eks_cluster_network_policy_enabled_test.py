from unittest import mock

from prowler.providers.aws.services.eks.eks_service import EKSCluster

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

cluster_name = "cluster_test"
cluster_arn = f"arn:aws:eks:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"


class Test_eks_cluster_network_policy_enabled:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_network_policy_enabled.eks_cluster_network_policy_enabled import (
                eks_cluster_network_policy_enabled,
            )

            check = eks_cluster_network_policy_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_cluster_without_sg(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_network_policy_enabled.eks_cluster_network_policy_enabled import (
                eks_cluster_network_policy_enabled,
            )

            check = eks_cluster_network_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} does not have a Network Policy. Cluster security group ID is not set."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    def test_cluster_with_sg(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION,
                logging=None,
                security_group_id="sg-123456789",
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_network_policy_enabled.eks_cluster_network_policy_enabled import (
                eks_cluster_network_policy_enabled,
            )

            check = eks_cluster_network_policy_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} has a Network Policy with the security group sg-123456789."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
