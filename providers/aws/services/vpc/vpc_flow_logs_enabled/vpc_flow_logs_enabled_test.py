from unittest import mock

from boto3 import client
from moto import mock_ec2

AWS_REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


class Test_vpc_flow_logs_enabled:
    @mock_ec2
    def test_vpc_only_default_vpcs(self):
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert (
                len(result) == 23
            )  # Number of AWS regions, one default VPC per region

    @mock_ec2
    def test_vpc_with_flow_logs(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        ec2_client.create_flow_logs(
            ResourceType="VPC",
            ResourceIds=[vpc["VpcId"]],
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="test_logs",
            DeliverLogsPermissionArn="arn:aws:iam::" + ACCOUNT_ID + ":role/test-role",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            # Search created VPC among default ones
            for result in result:
                if result.resource_id == vpc["VpcId"]:
                    assert result.status == "PASS"
                    assert (
                        result.status_extended
                        == f"VPC {vpc['VpcId']} Flow logs are enabled."
                    )
                    assert result.resource_id == vpc["VpcId"]

    @mock_ec2
    def test_vpc_without_flow_logs(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            # Search created VPC among default ones
            for result in result:
                if result.resource_id == vpc["VpcId"]:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"VPC {vpc['VpcId']} Flow logs are disabled."
                    )
                    assert result.resource_id == vpc["VpcId"]

    @mock_ec2
    def test_bad_response(self):
        mock_client = mock.MagicMock()

        with mock.patch(
            "providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 0
