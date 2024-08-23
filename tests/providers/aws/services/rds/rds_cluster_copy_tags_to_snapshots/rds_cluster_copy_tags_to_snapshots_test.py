from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_cluster_copy_tags_to_snapshots:
    @mock_aws
    def test_rds_no_clusters(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots import (
                    rds_cluster_copy_tags_to_snapshots,
                )

                check = rds_cluster_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_rds_cluster_without_copy_tags(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="test-cluster",
            AllocatedStorage=10,
            Engine="mysql",
            DatabaseName="staging-mysql",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            Tags=[],
            CopyTagsToSnapshot=False,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots import (
                    rds_cluster_copy_tags_to_snapshots,
                )

                check = rds_cluster_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster test-cluster does not have copy tags to snapshots enabled."
                )
                assert result[0].resource_id == "test-cluster"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:test-cluster"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_cluster_with_copy_tags(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="test-cluster",
            AllocatedStorage=10,
            Engine="mysql",
            DatabaseName="staging-mysql",
            DeletionProtection=True,
            DBClusterParameterGroupName="test",
            MasterUsername="test",
            MasterUserPassword="password",
            Tags=[],
            CopyTagsToSnapshot=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots.rds_client",
                new=RDS(aws_provider),
            ):
                from prowler.providers.aws.services.rds.rds_cluster_copy_tags_to_snapshots.rds_cluster_copy_tags_to_snapshots import (
                    rds_cluster_copy_tags_to_snapshots,
                )

                check = rds_cluster_copy_tags_to_snapshots()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster test-cluster has copy tags to snapshots enabled."
                )
                assert result[0].resource_id == "test-cluster"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:test-cluster"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
