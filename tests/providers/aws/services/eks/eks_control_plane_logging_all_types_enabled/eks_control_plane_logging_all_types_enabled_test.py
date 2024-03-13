from re import search
from unittest import mock

from prowler.providers.aws.services.eks.eks_service import (
    EKSCluster,
    EKSClusterLoggingEntity,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

cluster_name = "cluster_test"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)


class Test_eks_control_plane_logging_all_types_enabled:
    def test_no_clusters(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_logging_all_types_enabled.eks_control_plane_logging_all_types_enabled import (
                eks_control_plane_logging_all_types_enabled,
            )

            check = eks_control_plane_logging_all_types_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_control_plane_not_loggging(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=None,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_logging_all_types_enabled.eks_control_plane_logging_all_types_enabled import (
                eks_control_plane_logging_all_types_enabled,
            )

            check = eks_control_plane_logging_all_types_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Control plane logging is not enabled for EKS cluster",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn

    def test_control_plane_incomplete_loggging(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=EKSClusterLoggingEntity(
                    types=["api", "audit", "authenticator", "controllerManager"],
                    enabled=True,
                ),
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_logging_all_types_enabled.eks_control_plane_logging_all_types_enabled import (
                eks_control_plane_logging_all_types_enabled,
            )

            check = eks_control_plane_logging_all_types_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Control plane logging enabled but not all log types collected",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn

    def test_control_plane_complete_loggging(self):
        eks_client = mock.MagicMock
        eks_client.clusters = []
        eks_client.clusters.append(
            EKSCluster(
                name=cluster_name,
                arn=cluster_arn,
                region=AWS_REGION_EU_WEST_1,
                logging=EKSClusterLoggingEntity(
                    types=[
                        "api",
                        "audit",
                        "authenticator",
                        "controllerManager",
                        "scheduler",
                    ],
                    enabled=True,
                ),
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.eks.eks_service.EKS",
            eks_client,
        ):
            from prowler.providers.aws.services.eks.eks_control_plane_logging_all_types_enabled.eks_control_plane_logging_all_types_enabled import (
                eks_control_plane_logging_all_types_enabled,
            )

            check = eks_control_plane_logging_all_types_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Control plane logging enabled and correctly configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster_name
            assert result[0].resource_arn == cluster_arn
