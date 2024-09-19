from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.neptune.neptune_service import Cluster
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_neptune_cluster_integration_cloudwatch_logs:
    @mock_aws
    def test_neptune_no_instances(self):
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs import (
                    neptune_cluster_integration_cloudwatch_logs,
                )

                check = neptune_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_neptune_cluster_without_integration_cloudwatch_logs(self):
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
            DeletionProtection=False,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            EnableIAMDatabaseAuthentication=False,
            BackupRetentionPeriod=0,
            StorageEncrypted=False,
            Tags=[],
            EnableCloudwatchLogsExports=[],
        )
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs import (
                    neptune_cluster_integration_cloudwatch_logs,
                )

                check = neptune_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Neptune Cluster db-cluster-1 does not have cloudwatch audit logs enabled."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_neptune_cluster_with_integration_cloudwatch_logs_not_audit(self):
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
            EnableCloudwatchLogsExports=["slowquery"],
        )
        from prowler.providers.aws.services.neptune.neptune_service import Neptune

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs.neptune_client",
                new=Neptune(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs import (
                    neptune_cluster_integration_cloudwatch_logs,
                )

                check = neptune_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Neptune Cluster db-cluster-1 does not have cloudwatch audit logs enabled."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
                )
                assert result[0].resource_tags == []

    def test_neptune_cluster_with_integration_cloudwatch_logs_audit(self):
        neptune_client = mock.MagicMock
        cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
        neptune_client.clusters = {
            cluster_arn: Cluster(
                arn=cluster_arn,
                name="db-cluster-1",
                id="db-cluster-1",
                backup_retention_period=7,
                encrypted=True,
                kms_key="clave-kms",
                multi_az=False,
                iam_auth=True,
                deletion_protection=False,
                region="us-east-1",
                db_subnet_group_id="subnet-grupo-id",
                subnets=[
                    {
                        "SubnetIdentifier": "subnet-123",
                        "SubnetAvailabilityZone": {"Name": "us-east-1a"},
                        "SubnetStatus": "Active",
                    }
                ],
                tags=[],
                cloudwatch_logs=["audit"],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            new=neptune_client,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs.neptune_client",
            new=neptune_client,
        ):
            # Test Check
            from prowler.providers.aws.services.neptune.neptune_cluster_integration_cloudwatch_logs.neptune_cluster_integration_cloudwatch_logs import (
                neptune_cluster_integration_cloudwatch_logs,
            )

            check = neptune_cluster_integration_cloudwatch_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Neptune Cluster db-cluster-1 has cloudwatch audit logs enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []
