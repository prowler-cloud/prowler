from unittest import mock

import pytest
from boto3 import client, resource
from botocore.stub import Stubber
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_vpc_flow_logs_enabled:
    @pytest.mark.parametrize(
        "delivery_pages, expected_status, expected_delivery",
        [
            ([["FAILED"]], "FAIL", False),
            ([["FAILED", "FAILED"]], "FAIL", False),
            ([["SUCCESS"]], "PASS", True),
            ([["FAILED", "SUCCESS"]], "PASS", True),
            ([[None]], "MANUAL", None),
            ([["FAILED", None]], "MANUAL", None),
            ([["UNRECOGNIZED"]], "MANUAL", None),
            ([[]], "FAIL", None),
            ([["FAILED"], ["SUCCESS"]], "PASS", True),
            ([[], ["SUCCESS"]], "PASS", True),
            ([["FAILED"], [None]], "MANUAL", None),
        ],
        ids=[
            "failed",
            "all-failed",
            "success",
            "mixed-success",
            "missing",
            "failed-and-missing",
            "unknown",
            "no-flow-logs",
            "later-success",
            "empty-first-page",
            "later-missing",
        ],
    )
    @mock_aws
    def test_vpc_flow_log_delivery_status(
        self, delivery_pages, expected_status, expected_delivery
    ):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        inventory = VPC(aws_provider)
        inventory.vpcs = {
            arn: vpc for arn, vpc in inventory.vpcs.items() if vpc.id == vpc_id
        }
        regional_client = inventory.regional_clients[AWS_REGION_US_EAST_1]

        with Stubber(regional_client) as stubber:
            for index, statuses in enumerate(delivery_pages):
                flow_logs = []
                for status in statuses:
                    flow_log = {"ResourceId": vpc_id, "FlowLogStatus": "ACTIVE"}
                    if status is not None:
                        flow_log["DeliverLogsStatus"] = status
                    flow_logs.append(flow_log)
                response = {"FlowLogs": flow_logs}
                params = {"Filters": [{"Name": "resource-id", "Values": [vpc_id]}]}
                if index:
                    params["NextToken"] = f"page-{index + 1}"
                if index < len(delivery_pages) - 1:
                    response["NextToken"] = f"page-{index + 2}"
                stubber.add_response("describe_flow_logs", response, params)
            inventory._describe_flow_logs()
            stubber.assert_no_pending_responses()

        collected_vpc = next(iter(inventory.vpcs.values()))
        assert collected_vpc.flow_log is any(delivery_pages)
        assert collected_vpc.flow_log_delivery_success is expected_delivery

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=inventory,
            ),
        ):
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            result = vpc_flow_logs_enabled().execute()

            assert len(result) == 1
            assert result[0].status == expected_status
            assert result[0].resource_id == vpc_id
            assert result[0].region == AWS_REGION_US_EAST_1
            if not any(delivery_pages):
                message = "Flow logs are disabled."
            elif expected_status == "PASS":
                message = "Flow logs are enabled."
            elif expected_status == "FAIL":
                message = "Flow log delivery has failed for all configured flow logs."
            else:
                message = "Flow logs are configured but successful delivery could not be verified."
            assert result[0].status_extended == f"VPC {vpc_id} {message}"

    @mock_aws
    def test_vpc_only_default_vpcs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 2  # Number of AWS regions, one default VPC per region

    @pytest.mark.parametrize("destination_exists", [True, False])
    @mock_aws
    def test_vpc_with_flow_logs(self, destination_exists):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        if destination_exists:
            client("logs", region_name=AWS_REGION_US_EAST_1).create_log_group(
                logGroupName="test_logs"
            )

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
        flow_logs = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
        )["FlowLogs"]
        assert flow_logs[0]["DeliverLogsStatus"] == (
            "SUCCESS" if destination_exists else "FAILED"
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=VPC(aws_provider),
            ),
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
                    assert result.status == ("PASS" if destination_exists else "FAIL")
                    if destination_exists:
                        assert (
                            result.status_extended
                            == "VPC vpc_name Flow logs are enabled."
                        )
                    else:
                        assert result.status_extended == (
                            "VPC vpc_name Flow log delivery has failed for all configured flow logs."
                        )
                    assert result.resource_id == vpc["VpcId"]

    @mock_aws
    def test_vpc_without_flow_logs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=VPC(aws_provider),
            ),
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        aws_provider._scan_unused_services = False

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=VPC(aws_provider),
            ),
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
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        aws_provider._scan_unused_services = False

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=VPC(aws_provider),
            ),
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
