from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.rds.rds_service import DBCluster, DBInstance
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_multi_az:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_no_multi_az(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
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
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 does not have multi-AZ enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_multi_az(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            MultiAZ=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                    rds_instance_multi_az,
                )

                check = rds_instance_multi_az()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 has multi-AZ enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    def test_rds_instance_in_cluster_multi_az(self):
        rds_client = mock.MagicMock
        cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:test-cluster"
        rds_client.db_clusters = {
            cluster_arn: DBCluster(
                id="test-cluster",
                arn=cluster_arn,
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="",
                multi_az=True,
                username="test",
                iam_auth=False,
                backtrack=0,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="test-instance",
                arn=instance_arn,
                endpoint="",
                engine="aurora",
                engine_version="1.0.0",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group=[],
                multi_az=False,
                username="test",
                iam_auth=False,
                cluster_id="test-cluster",
                cluster_arn=cluster_arn,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "RDS Instance test-instance has multi-AZ enabled at cluster test-cluster level."
            )
            assert result[0].resource_id == "test-instance"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
            )
            assert result[0].resource_tags == []

    def test_rds_instance_in_cluster_without_multi_az(self):
        rds_client = mock.MagicMock
        cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:test-cluster"
        rds_client.db_clusters = {
            cluster_arn: DBCluster(
                id="test-cluster",
                arn=cluster_arn,
                endpoint="",
                engine="aurora",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group="",
                multi_az=False,
                username="test",
                iam_auth=False,
                backtrack=0,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="test-instance",
                arn=instance_arn,
                endpoint="",
                engine="aurora",
                engine_version="1.0.0",
                status="available",
                public=False,
                encrypted=False,
                auto_minor_version_upgrade=False,
                backup_retention_period=0,
                cloudwatch_logs=[],
                deletion_protection=False,
                parameter_group=[],
                multi_az=False,
                username="test",
                iam_auth=False,
                cluster_id="test-cluster",
                cluster_arn=cluster_arn,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "RDS Instance test-instance does not have multi-AZ enabled at cluster test-cluster level."
            )
            assert result[0].resource_id == "test-instance"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
            )
            assert result[0].resource_tags == []
