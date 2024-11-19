from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_rds_instance_no_public_access_fixer:
    @mock_aws
    def test_rds_private(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
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
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer import (
                    fixer,
                )

                assert fixer("db-primary-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_public(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ):

                # Test Fixer
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer import (
                    fixer,
                )

                assert fixer("db-primary-1", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_rds_cluster_public_snapshot_error(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer.rds_client",
                new=RDS(aws_provider),
            ):

                # Test Fixer
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access_fixer import (
                    fixer,
                )

                assert not fixer("db-primary-2", AWS_REGION_US_EAST_1)
