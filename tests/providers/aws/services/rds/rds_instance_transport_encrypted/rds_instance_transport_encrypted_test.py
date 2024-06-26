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
cluster_arn = (
    f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
)


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
class Test_rds_instance_transport_encrypted:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_aurora_instance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 connections are not encrypted."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_clustered_instance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DatabaseName="staging-postgres",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            Tags=[],
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 connections are not encrypted."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == cluster_arn
                assert result[0].resource_tags == []

    @mock_aws
    def test_postgres_rds_instance_no_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "rds.force_ssl",
                    "ParameterValue": "0",
                    "ApplyMethod": "immediate",
                },
            ],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 connections are not encrypted."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_mysql_rds_instance_no_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.mysql8.0",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mysql",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "require_secure_transport",
                    "ParameterValue": "0",
                    "ApplyMethod": "immediate",
                },
            ],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 connections are not encrypted."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_mysql_rds_instance_with_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.mysql8.0",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mysql",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "require_secure_transport",
                    "ParameterValue": "1",
                    "ApplyMethod": "immediate",
                },
            ],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 connections use SSL encryption."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_postgres_rds_instance_with_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "rds.force_ssl",
                    "ParameterValue": "1",
                    "ApplyMethod": "immediate",
                },
            ],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 connections use SSL encryption."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_postgres_clustered_instance_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DatabaseName="staging-postgres",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            Tags=[],
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ) as rds_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                # Change DB Cluster parameter group to support SSL since Moto does not support it
                rds_client.db_clusters[cluster_arn].require_secure_transport = "ON"
                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 connections use SSL encryption."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == cluster_arn
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_aurora_mysql_clustered_instance_ssl(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.mysql8.0",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            AllocatedStorage=10,
            Engine="aurora-mysql",
            DatabaseName="staging-mysql",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            Tags=[],
        )
        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "require_secure_transport",
                    "ParameterValue": "ON",
                    "ApplyMethod": "immediate",
                },
            ],
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted.rds_client",
                new=RDS(aws_provider),
            ) as rds_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_transport_encrypted.rds_instance_transport_encrypted import (
                    rds_instance_transport_encrypted,
                )

                # Change DB Cluster parameter group to support SSL since Moto does not support it
                rds_client.db_clusters[cluster_arn].require_secure_transport = "ON"
                check = rds_instance_transport_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster db-cluster-1 connections use SSL encryption."
                )
                assert result[0].resource_id == "db-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == cluster_arn
                assert result[0].resource_tags == []
