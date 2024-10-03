from unittest import mock

import botocore
from mock import MagicMock
from moto import mock_aws

from prowler.providers.aws.services.elasticache.elasticache_service import (
    ReplicationGroup,
)
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    AUTO_MINOR_VERSION_UPGRADE,
    AUTOMATIC_FAILOVER,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

REPLICATION_GROUP_ID = "clustered-redis"
REPLICATION_GROUP_ARN = f"arn:aws:elasticache:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:replicationgroup:{REPLICATION_GROUP_ID}"
REPLICATION_GROUP_STATUS = "available"
REPLICATION_GROUP_SNAPSHOT_RETENTION = "0"
REPLICATION_GROUP_ENCRYPTION = True
REPLICATION_GROUP_TRANSIT_ENCRYPTION = True
REPLICATION_GROUP_MULTI_AZ = "enabled"
REPLICATION_GROUP_TAGS = [
    {"Key": "environment", "Value": "test"},
]
# Patch every AWS call using Boto3
make_api_call = botocore.client.BaseClient._make_api_call


class Test_elasticache_redis_cluster_backup_enabled:
    @mock_aws
    def test_elasticache_no_replication_groups(self):

        # Mock ElastiCache Service
        elasticache_client = MagicMock
        elasticache_client.replication_groups = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_backup_enabled.elasticache_redis_cluster_backup_enabled import (
                elasticache_redis_cluster_backup_enabled,
            )

            check = elasticache_redis_cluster_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_cluster_backup_disabled(self):
        # Mock ElastiCache Service
        elasticache_client = MagicMock
        elasticache_client.replication_groups = {}

        elasticache_client.replication_groups[REPLICATION_GROUP_ARN] = ReplicationGroup(
            arn=REPLICATION_GROUP_ARN,
            id=REPLICATION_GROUP_ID,
            region=AWS_REGION_US_EAST_1,
            status=REPLICATION_GROUP_STATUS,
            snapshot_retention=0,
            encrypted=False,
            transit_encryption=False,
            multi_az=REPLICATION_GROUP_MULTI_AZ,
            tags=REPLICATION_GROUP_TAGS,
            auto_minor_version_upgrade=not AUTO_MINOR_VERSION_UPGRADE,
            automatic_failover=AUTOMATIC_FAILOVER,
            engine_version="6.0",
            auth_token_enabled=False,
        )

        elasticache_client.audit_config = {"minimum_snapshot_retention_period": 7}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_backup_enabled.elasticache_redis_cluster_backup_enabled import (
                elasticache_redis_cluster_backup_enabled,
            )

            check = elasticache_redis_cluster_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} does not have automated snapshot backups enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_cluster_backup_enabled(self):
        # Mock ElastiCache Service
        elasticache_client = MagicMock
        elasticache_client.replication_groups = {}

        elasticache_client.replication_groups[REPLICATION_GROUP_ARN] = ReplicationGroup(
            arn=REPLICATION_GROUP_ARN,
            id=REPLICATION_GROUP_ID,
            region=AWS_REGION_US_EAST_1,
            status=REPLICATION_GROUP_STATUS,
            snapshot_retention=9,
            encrypted=REPLICATION_GROUP_ENCRYPTION,
            transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
            multi_az=REPLICATION_GROUP_MULTI_AZ,
            tags=REPLICATION_GROUP_TAGS,
            auto_minor_version_upgrade=not AUTO_MINOR_VERSION_UPGRADE,
            automatic_failover=AUTOMATIC_FAILOVER,
            engine_version="6.0",
            auth_token_enabled=False,
        )

        elasticache_client.audit_config = {"minimum_snapshot_retention_period": 7}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_backup_enabled.elasticache_redis_cluster_backup_enabled import (
                elasticache_redis_cluster_backup_enabled,
            )

            check = elasticache_redis_cluster_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} has automated snapshot backups enabled with retention period 9 days."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_cluster_backup_enabled_modified_retention(self):
        # Mock ElastiCache Service
        elasticache_client = MagicMock
        elasticache_client.replication_groups = {}

        elasticache_client.replication_groups[REPLICATION_GROUP_ARN] = ReplicationGroup(
            arn=REPLICATION_GROUP_ARN,
            id=REPLICATION_GROUP_ID,
            region=AWS_REGION_US_EAST_1,
            status=REPLICATION_GROUP_STATUS,
            snapshot_retention=3,
            encrypted=REPLICATION_GROUP_ENCRYPTION,
            transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
            multi_az=REPLICATION_GROUP_MULTI_AZ,
            tags=REPLICATION_GROUP_TAGS,
            auto_minor_version_upgrade=not AUTO_MINOR_VERSION_UPGRADE,
            automatic_failover=AUTOMATIC_FAILOVER,
            engine_version="6.0",
            auth_token_enabled=False,
        )

        elasticache_client.audit_config = {"minimum_snapshot_retention_period": 1}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_backup_enabled.elasticache_redis_cluster_backup_enabled import (
                elasticache_redis_cluster_backup_enabled,
            )

            check = elasticache_redis_cluster_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} has automated snapshot backups enabled with retention period 3 days."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_cluster_backup_enabled_low_retention(self):
        # Mock ElastiCache Service
        elasticache_client = MagicMock
        elasticache_client.replication_groups = {}

        elasticache_client.replication_groups[REPLICATION_GROUP_ARN] = ReplicationGroup(
            arn=REPLICATION_GROUP_ARN,
            id=REPLICATION_GROUP_ID,
            region=AWS_REGION_US_EAST_1,
            status=REPLICATION_GROUP_STATUS,
            snapshot_retention=2,
            encrypted=REPLICATION_GROUP_ENCRYPTION,
            transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
            multi_az=REPLICATION_GROUP_MULTI_AZ,
            tags=REPLICATION_GROUP_TAGS,
            auto_minor_version_upgrade=not AUTO_MINOR_VERSION_UPGRADE,
            automatic_failover=AUTOMATIC_FAILOVER,
            engine_version="6.0",
            auth_token_enabled=False,
        )

        elasticache_client.audit_config = {"minimum_snapshot_retention_period": 3}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_backup_enabled.elasticache_redis_cluster_backup_enabled import (
                elasticache_redis_cluster_backup_enabled,
            )

            check = elasticache_redis_cluster_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} has automated snapshot backups enabled with retention period 2 days. Recommended to increase the snapshot retention period to a minimum of 7 days."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS
            assert result[0].check_metadata.Severity == "low"
