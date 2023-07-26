from re import search
from unittest import mock

from prowler.providers.aws.services.eks.eks_service import EKSCluster

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

cluster_name = "cluster_test"
cluster_arn = f"arn:aws:eks:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"


class Test_eks_cluster_kms_cmk_encryption_in_secrets_enabled:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_kms_cmk_encryption_in_secrets_enabled.eks_cluster_kms_cmk_encryption_in_secrets_enabled import (
                eks_cluster_kms_cmk_encryption_in_secrets_enabled,
            )

            check = eks_cluster_kms_cmk_encryption_in_secrets_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_not_secrets_encryption(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION,
                encryptionConfig=False,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_kms_cmk_encryption_in_secrets_enabled.eks_cluster_kms_cmk_encryption_in_secrets_enabled import (
                eks_cluster_kms_cmk_encryption_in_secrets_enabled,
            )

            check = eks_cluster_kms_cmk_encryption_in_secrets_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have encryption for Kubernetes secrets", result[0].status_extended
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn

    def test_secrets_encryption(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION,
                encryptionConfig=True,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_kms_cmk_encryption_in_secrets_enabled.eks_cluster_kms_cmk_encryption_in_secrets_enabled import (
                eks_cluster_kms_cmk_encryption_in_secrets_enabled,
            )

            check = eks_cluster_kms_cmk_encryption_in_secrets_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has encryption for Kubernetes secrets", result[0].status_extended
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
