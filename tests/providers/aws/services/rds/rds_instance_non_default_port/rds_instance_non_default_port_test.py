from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_non_default_port:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test del check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_using_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5432,  # Puerto por defecto para postgres
            Tags=[{"Key": "test", "Value": "test"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test del check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using the default port 5432 for postgres."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_instance_using_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-2",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="production-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5433,  # Puerto no por defecto para postgres
            Tags=[{"Key": "env", "Value": "production"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test del check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-2 is not using the default port 5433 for postgres."
                )
                assert result[0].resource_id == "db-master-2"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-2"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_instance_mariadb_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-3",
            AllocatedStorage=10,
            Engine="mariadb",
            DBName="staging-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3306,  # Puerto por defecto para mariadb
            Tags=[{"Key": "env", "Value": "staging"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test del check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-3 is using the default port 3306 for mariadb."
                )
                assert result[0].resource_id == "db-master-3"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-3"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_instance_mariadb_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-4",
            AllocatedStorage=10,
            Engine="mariadb",
            DBName="production-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3307,  # Puerto no por defecto para mariadb
            Tags=[{"Key": "env", "Value": "production"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test del check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-4 is not using the default port 3307 for mariadb."
                )
                assert result[0].resource_id == "db-master-4"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-4"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]
