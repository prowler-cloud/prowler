from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_copy_tags_to_snapshots_to_snapshots:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots import (
                    rds_instance_copy_tags_to_snapshots,
                )

                check = rds_instance_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_rds_aurora_instance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="test-instance",
            Engine="aurora-postgresql",
            DBInstanceClass="db.t2.micro",
            AllocatedStorage=5,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots import (
                    rds_instance_copy_tags_to_snapshots,
                )

                check = rds_instance_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_rds_instance_without_copy_tags(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="test-instance",
            Engine="mysql",
            DBInstanceClass="db.t2.micro",
            AllocatedStorage=5,
            CopyTagsToSnapshot=False,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots import (
                    rds_instance_copy_tags_to_snapshots,
                )

                check = rds_instance_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance test-instance does not have copy tags to snapshots enabled."
                )
                assert result[0].resource_id == "test-instance"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_with_copy_tags(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="test-instance",
            Engine="mysql",
            DBInstanceClass="db.t2.micro",
            AllocatedStorage=5,
            CopyTagsToSnapshot=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_instance_copy_tags_to_snapshots.rds_instance_copy_tags_to_snapshots import (
                    rds_instance_copy_tags_to_snapshots,
                )

                check = rds_instance_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance test-instance has copy tags to snapshots enabled."
                )
                assert result[0].resource_id == "test-instance"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:test-instance"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
