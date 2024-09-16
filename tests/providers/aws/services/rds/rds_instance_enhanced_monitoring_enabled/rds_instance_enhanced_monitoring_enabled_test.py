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
class Test_rds_instance_enhanced_monitoring_enabled:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                    rds_instance_enhanced_monitoring_enabled,
                )

                check = rds_instance_enhanced_monitoring_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_no_monitoring(self):
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
                "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                    rds_instance_enhanced_monitoring_enabled,
                )

                check = rds_instance_enhanced_monitoring_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 does not have enhanced monitoring enabled."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_with_monitoring(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance_id = "db-master-1"
        conn.create_db_instance(
            DBInstanceIdentifier=instance_id,
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
                "prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled.rds_client",
                new=RDS(aws_provider),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_enhanced_monitoring_enabled.rds_instance_enhanced_monitoring_enabled import (
                    rds_instance_enhanced_monitoring_enabled,
                )

                instance_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{instance_id}"
                service_client.db_instances[instance_arn].enhanced_monitoring_arn = (
                    "log-stream"
                )

                check = rds_instance_enhanced_monitoring_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"RDS Instance {instance_id} has enhanced monitoring enabled."
                )
                assert result[0].resource_id == instance_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == instance_arn
                assert result[0].resource_tags == []
