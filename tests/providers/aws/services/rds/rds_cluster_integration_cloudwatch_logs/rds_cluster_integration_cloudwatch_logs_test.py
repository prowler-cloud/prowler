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
    if operation_name == "CreateDBCluster":
        return {
            "DBClusterIdentifier": "cluster-1",
            "Engine": "aurora",
            "MasterUsername": "admin",
            "MasterUserPassword": "password",
        }

    return make_api_call(self, operation_name, kwarg)


class Test_rds_cluster_integration_cloudwatch_logs:
    @mock_aws
    def test_rds_no_clusters(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs import (
                    rds_cluster_integration_cloudwatch_logs,
                )

                check = rds_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_no_valid_cluster(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call
        ):
            conn = client("rds", region_name=AWS_REGION_US_EAST_1)
            conn.create_db_cluster(
                DBClusterIdentifier="cluster-1",
                Engine="aurora",
                MasterUsername="admin",
                MasterUserPassword="password",
            )

            from prowler.providers.aws.services.rds.rds_service import RDS

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs.rds_client",
                    new=RDS(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs import (
                        rds_cluster_integration_cloudwatch_logs,
                    )

                    check = rds_cluster_integration_cloudwatch_logs()
                    result = check.execute()

                    assert len(result) == 0

    @mock_aws
    def test_rds_cluster_no_logs(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="aurora-cluster-1",
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="password",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs import (
                    rds_cluster_integration_cloudwatch_logs,
                )

                check = rds_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Cluster aurora-cluster-1 does not have CloudWatch Logs enabled."
                )
                assert result[0].resource_id == "aurora-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:aurora-cluster-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_cluster_with_logs(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="aurora-cluster-1",
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="password",
            EnableCloudwatchLogsExports=["audit", "error"],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_integration_cloudwatch_logs.rds_cluster_integration_cloudwatch_logs import (
                    rds_cluster_integration_cloudwatch_logs,
                )

                check = rds_cluster_integration_cloudwatch_logs()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Cluster aurora-cluster-1 is shipping audit, error logs to CloudWatch Logs."
                )
                assert result[0].resource_id == "aurora-cluster-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:aurora-cluster-1"
                )
                assert result[0].resource_tags == []
