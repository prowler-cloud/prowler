from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_vpc_flow_logs_enabled:
    @mock_aws
    def test_vpc_only_default_vpcs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 2  # Number of AWS regions, one default VPC per region

    @mock_aws
    def test_vpc_with_flow_logs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": "vpc_name"},
                    ],
                },
            ],
        )["Vpc"]

        ec2_client.create_flow_logs(
            ResourceType="VPC",
            ResourceIds=[vpc["VpcId"]],
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="test_logs",
            DeliverLogsPermissionArn="arn:aws:iam::"
            + AWS_ACCOUNT_NUMBER
            + ":role/test-role",
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            # Search created VPC among default ones
            for result in result:
                if result.resource_id == vpc["VpcId"]:
                    assert result.status == "PASS"
                    assert (
                        result.status_extended == "VPC vpc_name Flow logs are enabled."
                    )
                    assert result.resource_id == vpc["VpcId"]

    @mock_aws
    def test_vpc_without_flow_logs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
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

    @mock_aws
    def test_vpc_without_flow_logs_ignoring(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_vpc_without_flow_logs_ignoring_in_use(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        ec2.create_network_interface(SubnetId=subnet.id)
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            # Search created VPC among default ones
            for result in result:
                if result.resource_id == vpc.id:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"VPC {vpc.id} Flow logs are disabled."
                    )
                    assert result.resource_id == vpc.id
