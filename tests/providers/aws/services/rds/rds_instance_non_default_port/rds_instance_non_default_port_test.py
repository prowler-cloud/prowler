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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_aurora_postgres_using_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5432,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using the default port 5432 for aurora-postgresql."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_instance_aurora_postgres_using_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-2",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="production-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5433,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-2 is not using the default port 5433 for aurora-postgresql."
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
    def test_rds_instance_postgres_using_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-3",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5432,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-3 is using the default port 5432 for postgres."
                )
                assert result[0].resource_id == "db-master-3"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-3"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_instance_postgres_using_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-4",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="production-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5433,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-4 is not using the default port 5433 for postgres."
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

    @mock_aws
    def test_rds_instance_mysql_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-5",
            AllocatedStorage=10,
            Engine="mysql",
            DBName="staging-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3306,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-5 is using the default port 3306 for mysql."
                )
                assert result[0].resource_id == "db-master-5"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-5"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_instance_mysql_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-6",
            AllocatedStorage=10,
            Engine="mysql",
            DBName="production-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3307,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-6 is not using the default port 3307 for mysql."
                )
                assert result[0].resource_id == "db-master-6"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-6"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_instance_aurora_mysql_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-7",
            AllocatedStorage=10,
            Engine="aurora-mysql",
            DBName="staging-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3306,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-7 is using the default port 3306 for aurora-mysql."
                )
                assert result[0].resource_id == "db-master-7"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-7"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_instance_aurora_mysql_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-8",
            AllocatedStorage=10,
            Engine="aurora-mysql",
            DBName="production-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3307,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-8 is not using the default port 3307 for aurora-mysql."
                )
                assert result[0].resource_id == "db-master-8"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-8"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_instance_mariadb_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-9",
            AllocatedStorage=10,
            Engine="mariadb",
            DBName="staging-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3306,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-9 is using the default port 3306 for mariadb."
                )
                assert result[0].resource_id == "db-master-9"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-9"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_instance_mariadb_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-10",
            AllocatedStorage=10,
            Engine="mariadb",
            DBName="production-mariadb",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=3307,
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
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-10 is not using the default port 3307 for mariadb."
                )
                assert result[0].resource_id == "db-master-10"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-10"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]
