from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_bedrock_access_private_connectivity_enforced:
    @mock_aws
    def test_no_resources(self):
        """Test when no VPCs exist (scan_unused_services=False and no in_use VPCs)."""
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced import (
                bedrock_access_private_connectivity_enforced,
            )

            check = bedrock_access_private_connectivity_enforced()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_vpc_no_bedrock_endpoint(self):
        """Test FAIL: VPC exists but has no Bedrock Runtime VPC endpoint."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced import (
                bedrock_access_private_connectivity_enforced,
            )

            check = bedrock_access_private_connectivity_enforced()
            result = check.execute()

            # Default VPC + created VPC, both should FAIL
            vpc_ids = [r.resource_id for r in result]
            assert vpc["VpcId"] in vpc_ids

            for finding in result:
                if finding.resource_id == vpc["VpcId"]:
                    assert finding.status == "FAIL"
                    assert finding.region == AWS_REGION_US_EAST_1
                    assert (
                        finding.status_extended
                        == f"VPC {vpc['VpcId']} does not have a Bedrock Runtime VPC endpoint configured to enforce private connectivity."
                    )
                    assert (
                        finding.resource_arn
                        == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                    )

    @mock_aws
    def test_vpc_with_bedrock_runtime_endpoint(self):
        """Test PASS: VPC has a Bedrock Runtime VPC endpoint configured."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])[
            "RouteTable"
        ]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced import (
                bedrock_access_private_connectivity_enforced,
            )

            check = bedrock_access_private_connectivity_enforced()
            result = check.execute()

            # Find the result for our VPC
            for finding in result:
                if finding.resource_id == vpc["VpcId"]:
                    assert finding.status == "PASS"
                    assert finding.region == AWS_REGION_US_EAST_1
                    assert (
                        finding.status_extended
                        == f"VPC {vpc['VpcId']} has a Bedrock Runtime Interface VPC endpoint configured to enforce private connectivity."
                    )
                    assert (
                        finding.resource_arn
                        == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                    )
                    break
            else:
                raise AssertionError(
                    f"No finding found for VPC {vpc['VpcId']}"
                )

    @mock_aws
    def test_vpc_with_non_bedrock_endpoint(self):
        """Test FAIL: VPC has a VPC endpoint but not for Bedrock Runtime."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])[
            "RouteTable"
        ]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced import (
                bedrock_access_private_connectivity_enforced,
            )

            check = bedrock_access_private_connectivity_enforced()
            result = check.execute()

            for finding in result:
                if finding.resource_id == vpc["VpcId"]:
                    assert finding.status == "FAIL"
                    assert finding.region == AWS_REGION_US_EAST_1
                    assert (
                        finding.status_extended
                        == f"VPC {vpc['VpcId']} does not have a Bedrock Runtime VPC endpoint configured to enforce private connectivity."
                    )
                    break
            else:
                raise AssertionError(
                    f"No finding found for VPC {vpc['VpcId']}"
                )

    @mock_aws
    def test_vpc_not_in_use_scan_unused_false(self):
        """Test that unused VPCs are skipped when scan_unused_services is False."""
        # The default VPC created by moto is not in_use
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_access_private_connectivity_enforced.bedrock_access_private_connectivity_enforced import (
                bedrock_access_private_connectivity_enforced,
            )

            check = bedrock_access_private_connectivity_enforced()
            result = check.execute()

            # Default VPC is not in_use and scan_unused_services is False
            assert len(result) == 0
