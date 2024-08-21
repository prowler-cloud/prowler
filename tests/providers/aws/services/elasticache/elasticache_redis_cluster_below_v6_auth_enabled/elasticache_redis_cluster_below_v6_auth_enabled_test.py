from unittest import mock

from mock import MagicMock, patch
from moto import mock_aws

from prowler.providers.aws.services.elasticache.elasticache_service import Cluster
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    ELASTICACHE_CLUSTER_ARN,
    ELASTICACHE_CLUSTER_NAME,
    ELASTICACHE_CLUSTER_TAGS,
    ELASTICACHE_ENGINE,
    ELASTICACHE_ENGINE_MEMCACHED,
    mock_make_api_call,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_elasticache_redis_cluster_below_v6_auth_enabled:
    @mock_aws
    def test_elasticache_no_clusters(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_below_v6_auth_enabled.elasticache_redis_cluster_below_v6_auth_enabled import (
                elasticache_redis_cluster_below_v6_auth_enabled,
            )

            check = elasticache_redis_cluster_below_v6_auth_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_no_redis_clusters(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            engine=ELASTICACHE_ENGINE_MEMCACHED,
            region=AWS_REGION_US_EAST_1,
            tags=ELASTICACHE_CLUSTER_TAGS,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_below_v6_auth_enabled.elasticache_redis_cluster_below_v6_auth_enabled import (
                elasticache_redis_cluster_below_v6_auth_enabled,
            )

            check = elasticache_redis_cluster_below_v6_auth_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_no_redis_clusters_below_v6(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        version = "6.0.0"
        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            engine=ELASTICACHE_ENGINE_MEMCACHED,
            region=AWS_REGION_US_EAST_1,
            tags=ELASTICACHE_CLUSTER_TAGS,
            engine_version=version,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_below_v6_auth_enabled.elasticache_redis_cluster_below_v6_auth_enabled import (
                elasticache_redis_cluster_below_v6_auth_enabled,
            )

            check = elasticache_redis_cluster_below_v6_auth_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_redis_cluster_below_v6_auth_enabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        version = "5.0.0"
        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            engine=ELASTICACHE_ENGINE,
            region=AWS_REGION_US_EAST_1,
            tags=ELASTICACHE_CLUSTER_TAGS,
            auth_token_enabled=True,
            engine_version=version,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_below_v6_auth_enabled.elasticache_redis_cluster_below_v6_auth_enabled import (
                elasticache_redis_cluster_below_v6_auth_enabled,
            )

            check = elasticache_redis_cluster_below_v6_auth_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {ELASTICACHE_CLUSTER_NAME} (v{version}) does have AUTH enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == ELASTICACHE_CLUSTER_NAME
            assert result[0].resource_arn == ELASTICACHE_CLUSTER_ARN
            assert result[0].resource_tags == ELASTICACHE_CLUSTER_TAGS

    def test_elasticache_redis_cluster_below_v6_auth_disabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        version = "5.0.0"
        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            engine=ELASTICACHE_ENGINE,
            region=AWS_REGION_US_EAST_1,
            tags=ELASTICACHE_CLUSTER_TAGS,
            auth_token_enabled=False,
            engine_version=version,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_below_v6_auth_enabled.elasticache_redis_cluster_below_v6_auth_enabled import (
                elasticache_redis_cluster_below_v6_auth_enabled,
            )

            check = elasticache_redis_cluster_below_v6_auth_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {ELASTICACHE_CLUSTER_NAME} does not have automated minor version upgrades enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == ELASTICACHE_CLUSTER_NAME
            assert result[0].resource_arn == ELASTICACHE_CLUSTER_ARN
            assert result[0].resource_tags == ELASTICACHE_CLUSTER_TAGS
