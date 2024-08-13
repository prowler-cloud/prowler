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
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 0

    def test_eks_cluster_not_using_a_supported_minor_version(self):
        eks_client = mock.MagicMock
        eks_client.audit_config = {"eks_cluster_oldest_version_supported": "1.28"}
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="1.22",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} is in version 1.22. It should be one of the next supported versions: 1.28 or higher"
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_eks_cluster_not_using_a_supported_major_version(self):
        eks_client = mock.MagicMock
        eks_client.audit_config = {"eks_cluster_oldest_version_supported": "1.28"}
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="0.22",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} is in version 0.22. It should be one of the next supported versions: 1.28 or higher"
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_eks_cluster_using_a_supported_version_ver_1_28(self):
        eks_client = mock.MagicMock
        eks_client.audit_config = {"eks_cluster_oldest_version_supported": "1.28"}
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="1.28",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} is using version 1.28 that is supported by AWS."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_eks_cluster_using_a_supported_version_ver_1_29(self):
        eks_client = mock.MagicMock
        eks_client.audit_config = {"eks_cluster_oldest_version_supported": "1.28"}
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="1.29",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} is using version 1.29 that is supported by AWS."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_eks_cluster_using_a_supported_version_ver_1_30(self):
        eks_client = mock.MagicMock
        eks_client.audit_config = {"eks_cluster_oldest_version_supported": "1.28"}
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                version="1.30",
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_cluster_uses_a_supported_version.eks_cluster_uses_a_supported_version import (
                eks_cluster_uses_a_supported_version,
            )

            check = eks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EKS cluster {cluster_name} is using version 1.30 that is supported by AWS."
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
