from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_cluster_non_default_port:
    @mock_aws
    def test_rds_no_clusters(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_cluster_aurora_postgres_using_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 is using the default port 5432 for aurora-postgresql."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_cluster_aurora_postgres_using_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-2",
            Engine="aurora-postgresql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-2 is not using the default port 5433 for aurora-postgresql."
                )
                assert result[0].resource_id == "db-cluster-2"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-2"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_cluster_postgres_using_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-3",
            Engine="postgres",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-3 is using the default port 5432 for postgres."
                )
                assert result[0].resource_id == "db-cluster-3"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-3"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_cluster_postgres_using_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-4",
            Engine="postgres",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-4 is not using the default port 5433 for postgres."
                )
                assert result[0].resource_id == "db-cluster-4"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-4"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_cluster_aurora_mysql_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-5",
            Engine="aurora-mysql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-5 is using the default port 3306 for aurora-mysql."
                )
                assert result[0].resource_id == "db-cluster-5"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-5"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_cluster_aurora_mysql_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-6",
            Engine="aurora-mysql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-6 is not using the default port 3307 for aurora-mysql."
                )
                assert result[0].resource_id == "db-cluster-6"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-6"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]

    @mock_aws
    def test_rds_cluster_mysql_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-7",
            Engine="mysql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-7 is using the default port 3306 for mysql."
                )
                assert result[0].resource_id == "db-cluster-7"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-7"
                )
                assert result[0].resource_tags == [{"Key": "env", "Value": "staging"}]

    @mock_aws
    def test_rds_cluster_mysql_non_default_port(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-8",
            Engine="mysql",
            StorageEncrypted=True,
            DeletionProtection=True,
            MasterUsername="cluster",
            MasterUserPassword="password",
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
                "prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_non_default_port.rds_cluster_non_default_port import (
                    rds_cluster_non_default_port,
                )

                check = rds_cluster_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-8 is not using the default port 3307 for mysql."
                )
                assert result[0].resource_id == "db-cluster-8"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-8"
                )
                assert result[0].resource_tags == [
                    {"Key": "env", "Value": "production"}
                ]
