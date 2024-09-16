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
class Test_rds_instance_backup_enabled:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled import (
                    rds_instance_backup_enabled,
                )

                check = rds_instance_backup_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_no_backup(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance_id = "db-master-1"
        conn.create_db_instance(
            DBInstanceIdentifier=instance_id,
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled import (
                    rds_instance_backup_enabled,
                )

                instance_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{instance_id}"
                service_client.db_instances[instance_arn].backup_retention_period = 0

                check = rds_instance_backup_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"RDS Instance {instance_id} does not have backup enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_with_backup(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance_id = "db-master-1"
        retention_period = 10
        conn.create_db_instance(
            DBInstanceIdentifier=instance_id,
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            BackupRetentionPeriod=retention_period,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled import (
                    rds_instance_backup_enabled,
                )

                check = rds_instance_backup_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"RDS Instance {instance_id} has backup enabled with retention period {retention_period} days."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_replica_with_backup_checking_replicas(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance_id = "db-master-1"
        retention_period = 10
        conn.create_db_instance(
            DBInstanceIdentifier=instance_id,
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            BackupRetentionPeriod=retention_period,
        )
        replica_id = "db-replica-1"
        conn.create_db_instance_read_replica(
            DBInstanceIdentifier=replica_id,
            SourceDBInstanceIdentifier="db-master-1",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"check_rds_instance_replicas": True}
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled import (
                    rds_instance_backup_enabled,
                )

                check = rds_instance_backup_enabled()
                result = check.execute()

                assert len(result) == 2

                for finding in result:
                    if finding.resource_id == instance_id:
                        assert finding.status == "PASS"
                        assert (
                            finding.status_extended
                            == f"RDS Instance {instance_id} has backup enabled with retention period {retention_period} days."
                        )

                        assert finding.resource_id == instance_id
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert (
                            finding.resource_arn
                            == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{instance_id}"
                        )
                        assert finding.resource_tags == []
                    if finding.resource_id == replica_id:
                        assert finding.status == "PASS"
                        assert (
                            finding.status_extended
                            == f"RDS Instance {replica_id} has backup enabled with retention period {retention_period} days."
                        )

                        assert finding.resource_id == replica_id
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert (
                            finding.resource_arn
                            == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{replica_id}"
                        )
                        assert finding.resource_tags == []

    @mock_aws
    def test_rds_instance_replica_with_backup_default_config(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance_id = "db-master-1"
        retention_period = 10
        conn.create_db_instance(
            DBInstanceIdentifier=instance_id,
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            BackupRetentionPeriod=retention_period,
        )
        replica_id = "db-replica-1"
        conn.create_db_instance_read_replica(
            DBInstanceIdentifier=replica_id,
            SourceDBInstanceIdentifier=instance_id,
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_backup_enabled.rds_instance_backup_enabled import (
                    rds_instance_backup_enabled,
                )

                check = rds_instance_backup_enabled()
                result = check.execute()

                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"RDS Instance {instance_id} has backup enabled with retention period {retention_period} days."
                )

                assert result[0].resource_id == instance_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{instance_id}"
                )
                assert result[0].resource_tags == []
