from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }

    return make_api_call(self, operation_name, kwarg)


@mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_neptune_cluster_storage_encrypted:
    @mock_aws
    def test_neptune_no_instances(self):
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted import (
                    neptune_cluster_storage_encrypted,
                )

                check = neptune_cluster_storage_encrypted()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_neptune_cluster_without_storage_encrypted(self):
        conn = client("neptune", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.neptune",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="neptune",
            DatabaseName="test-1",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            EnableIAMDatabaseAuthentication=False,
            BackupRetentionPeriod=0,
            StorageEncrypted=False,
            Tags=[],
        )
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted import (
                    neptune_cluster_storage_encrypted,
                )

                check = neptune_cluster_storage_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Neptune Cluster db-cluster-1 is not encrypted at rest."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_neptune_cluster_with_storage_encrypted(self):
        conn = client("neptune", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.neptune",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="neptune",
            DatabaseName="test-1",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            BackupRetentionPeriod=0,
            StorageEncrypted=True,
            Tags=[],
        )
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_storage_encrypted.neptune_cluster_storage_encrypted import (
                    neptune_cluster_storage_encrypted,
                )

                check = neptune_cluster_storage_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Neptune Cluster db-cluster-1 is encrypted at rest."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
                )
                assert result[0].resource_tags == []
