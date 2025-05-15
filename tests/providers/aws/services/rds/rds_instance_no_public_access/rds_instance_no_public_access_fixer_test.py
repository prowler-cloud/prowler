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
                    RdsInstanceNoPublicAccessFixer,
                )

                fixer = RdsInstanceNoPublicAccessFixer()
                assert fixer.fix(
                    None, region=AWS_REGION_US_EAST_1, resource_id="db-primary-1"
                )

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
                    RdsInstanceNoPublicAccessFixer,
                )

                fixer = RdsInstanceNoPublicAccessFixer()
                # Test with finding
                mock_finding = {
                    "Region": AWS_REGION_US_EAST_1,
                    "ResourceId": "db-primary-1",
                    "Status": "FAIL",
                }
                assert fixer.fix(finding=mock_finding)

                # Test with kwargs
                assert fixer.fix(
                    None, region=AWS_REGION_US_EAST_1, resource_id="db-primary-1"
                )

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
                    RdsInstanceNoPublicAccessFixer,
                )

                fixer = RdsInstanceNoPublicAccessFixer()
                assert not fixer.fix(
                    None, region=AWS_REGION_US_EAST_1, resource_id="db-primary-2"
                )

    @mock_aws
    def test_rds_error_handling(self):
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
                    RdsInstanceNoPublicAccessFixer,
                )

                fixer = RdsInstanceNoPublicAccessFixer()

                # Test with non-existent instance
                assert not fixer.fix(
                    None, region=AWS_REGION_US_EAST_1, resource_id="db-primary-2"
                )

                # Test with missing parameters
                assert not fixer.fix(None)
                assert not fixer.fix(None, region=AWS_REGION_US_EAST_1)
                assert not fixer.fix(None, resource_id="db-primary-1")

                # Test with invalid finding format
                invalid_finding = {"wrong_key": "wrong_value"}
                assert not fixer.fix(finding=invalid_finding)
