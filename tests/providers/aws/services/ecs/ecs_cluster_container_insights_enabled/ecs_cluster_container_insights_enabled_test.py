from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CLUSTER_NAME = "test-cluster"


class Test_ecs_clusters_container_insights_enabled:
    @mock_aws
    def test_no_clusters(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled.ecs_client",
            new=ECS(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled import (
                ecs_cluster_container_insights_enabled,
            )

            check = ecs_cluster_container_insights_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_cluster_no_settings(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)
        cluster_arn = ecs_client.create_cluster(
            clusterName=CLUSTER_NAME,
        )[
            "cluster"
        ]["clusterArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled.ecs_client",
            new=ECS(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled import (
                ecs_cluster_container_insights_enabled,
            )

            check = ecs_cluster_container_insights_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == cluster_arn
            assert (
                result[0].status_extended
                == f"ECS cluster {CLUSTER_NAME} does not have container insights enabled."
            )

    @mock_aws
    def test_cluster_enabled_container_insights(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)
        cluster_settings = [
            {"name": "containerInsights", "value": "enabled"},
        ]
        cluster_arn = ecs_client.create_cluster(
            clusterName=CLUSTER_NAME,
            settings=cluster_settings,
        )["cluster"]["clusterArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled.ecs_client",
            new=ECS(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled import (
                ecs_cluster_container_insights_enabled,
            )

            check = ecs_cluster_container_insights_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_arn == cluster_arn
            assert (
                result[0].status_extended
                == f"ECS cluster {CLUSTER_NAME} has container insights enabled."
            )

    @mock_aws
    def test_cluster_disabled_container_insights(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)
        cluster_settings = [
            {"name": "containerInsights", "value": "disabled"},
        ]
        cluster_arn = ecs_client.create_cluster(
            clusterName=CLUSTER_NAME,
            settings=cluster_settings,
        )["cluster"]["clusterArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled.ecs_client",
            new=ECS(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_cluster_container_insights_enabled.ecs_cluster_container_insights_enabled import (
                ecs_cluster_container_insights_enabled,
            )

            check = ecs_cluster_container_insights_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == cluster_arn
            assert (
                result[0].status_extended
                == f"ECS cluster {CLUSTER_NAME} does not have container insights enabled."
            )
