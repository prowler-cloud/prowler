from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.bedrock.bedrock_service import (
    Guardrail,
    LoggingConfiguration,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

BEDROCK_SERVICES = [
    "com.amazonaws.us-east-1.bedrock",
    "com.amazonaws.us-east-1.bedrock-runtime",
    "com.amazonaws.us-east-1.bedrock-agent",
    "com.amazonaws.us-east-1.bedrock-agent-runtime",
    "com.amazonaws.us-east-1.bedrock-mantle",
]

MOCK_BEDROCK_CLIENT = mock.MagicMock(
    logging_configurations={AWS_REGION_US_EAST_1: LoggingConfiguration(enabled=True)},
    guardrails={},
)

MOCK_BEDROCK_AGENT_CLIENT = mock.MagicMock(agents={})

MOCK_BEDROCK_CLIENT_NO_ACTIVITY = mock.MagicMock(
    logging_configurations={AWS_REGION_US_EAST_1: LoggingConfiguration(enabled=False)},
    guardrails={},
)

MOCK_BEDROCK_AGENT_CLIENT_NO_ACTIVITY = mock.MagicMock(agents={})

CHECK_MODULE = "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured"


class Test_bedrock_vpc_endpoints_configured:
    @mock_aws
    def test_no_resources(self):
        """Test with no in-use VPCs and scan_unused_services disabled - should return no results."""
        client("ec2", region_name=AWS_REGION_US_EAST_1)

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_no_bedrock_activity(self):
        """Test VPCs in region with no Bedrock activity - should return no results."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.describe_vpcs()

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT_NO_ACTIVITY,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT_NO_ACTIVITY,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_no_endpoints(self):
        """Test VPC with no VPC endpoints at all - should FAIL with all services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 1
                assert result[0].resource_id == vpc_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert "Bedrock control plane" in result[0].status_extended
                assert "Bedrock runtime" in result[0].status_extended
                assert "Bedrock agent control plane" in result[0].status_extended
                assert "Bedrock agent runtime" in result[0].status_extended
                assert "Bedrock Mantle" in result[0].status_extended

    @mock_aws
    def test_vpc_only_bedrock_runtime_endpoint(self):
        """Test VPC with only Bedrock runtime endpoint - should FAIL with three services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                # Default VPC + created VPC
                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.region == AWS_REGION_US_EAST_1
                assert finding.status == "FAIL"
                assert "Bedrock runtime" not in finding.status_extended
                assert "Bedrock control plane" in finding.status_extended
                assert "Bedrock agent control plane" in finding.status_extended
                assert "Bedrock agent runtime" in finding.status_extended
                assert "Bedrock Mantle" in finding.status_extended
                assert (
                    finding.resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                )

    @mock_aws
    def test_vpc_only_bedrock_agent_runtime_endpoint(self):
        """Test VPC with only Bedrock agent runtime endpoint - should FAIL with three services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-agent-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.region == AWS_REGION_US_EAST_1
                assert finding.status == "FAIL"
                assert "Bedrock agent runtime" not in finding.status_extended
                assert "Bedrock control plane" in finding.status_extended
                assert "Bedrock runtime" in finding.status_extended
                assert "Bedrock agent control plane" in finding.status_extended
                assert "Bedrock Mantle" in finding.status_extended
                assert (
                    finding.resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                )

    @mock_aws
    def test_vpc_all_bedrock_endpoints(self):
        """Test VPC with all four Bedrock endpoints - should PASS."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        vpc_default_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        for svc in BEDROCK_SERVICES:
            ec2_client.create_vpc_endpoint(
                VpcId=vpc["VpcId"],
                ServiceName=svc,
                RouteTableIds=[route_table["RouteTableId"]],
                VpcEndpointType="Interface",
            )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.region == AWS_REGION_US_EAST_1
                assert finding.status == "PASS"
                assert (
                    finding.status_extended
                    == f"VPC {vpc['VpcId']} has VPC endpoints for all Bedrock services."
                )
                assert (
                    finding.resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                )

                # Default VPC should FAIL
                default_finding = next(
                    f for f in result if f.resource_id == vpc_default_id
                )
                assert default_finding.status == "FAIL"

    @mock_aws
    def test_vpc_only_runtime_endpoints(self):
        """Test VPC with only both runtime endpoints but missing control plane endpoints - should FAIL."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-agent-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.status == "FAIL"
                assert "Bedrock control plane" in finding.status_extended
                assert "Bedrock agent control plane" in finding.status_extended
                assert "Bedrock Mantle" in finding.status_extended
                assert "Bedrock runtime" not in finding.status_extended
                assert "Bedrock agent runtime" not in finding.status_extended

    @mock_aws
    def test_vpc_unrelated_endpoint_only(self):
        """Test VPC with only an unrelated endpoint (S3) - should FAIL with all services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.region == AWS_REGION_US_EAST_1
                assert finding.status == "FAIL"
                assert "Bedrock control plane" in finding.status_extended
                assert "Bedrock runtime" in finding.status_extended
                assert "Bedrock agent control plane" in finding.status_extended
                assert "Bedrock agent runtime" in finding.status_extended
                assert "Bedrock Mantle" in finding.status_extended

    @mock_aws
    def test_vpc_only_bedrock_mantle_endpoint(self):
        """Test VPC with only Bedrock Mantle endpoint - should FAIL with four services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-mantle",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=MOCK_BEDROCK_CLIENT,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 2
                finding = next(f for f in result if f.resource_id == vpc["VpcId"])
                assert finding.status == "FAIL"
                assert "Bedrock Mantle" not in finding.status_extended
                assert "Bedrock control plane" in finding.status_extended
                assert "Bedrock runtime" in finding.status_extended
                assert "Bedrock agent control plane" in finding.status_extended
                assert "Bedrock agent runtime" in finding.status_extended

    @mock_aws
    def test_bedrock_activity_via_guardrail(self):
        """Test that Bedrock activity is detected via guardrails."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_with_guardrail = mock.MagicMock(
            logging_configurations={
                AWS_REGION_US_EAST_1: LoggingConfiguration(enabled=False)
            },
            guardrails={
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/test": Guardrail(
                    id="test",
                    name="test-guardrail",
                    arn="arn:aws:bedrock:us-east-1:123456789012:guardrail/test",
                    region=AWS_REGION_US_EAST_1,
                )
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_client",
                    new=bedrock_with_guardrail,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.bedrock_agent_client",
                    new=MOCK_BEDROCK_AGENT_CLIENT_NO_ACTIVITY,
                ),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                # Region has Bedrock activity via guardrail, so VPC should be checked
                assert len(result) == 1
                assert result[0].resource_id == vpc_id
                assert result[0].status == "FAIL"
