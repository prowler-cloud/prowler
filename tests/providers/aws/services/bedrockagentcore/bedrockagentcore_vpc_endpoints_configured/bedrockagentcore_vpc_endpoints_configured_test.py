from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreRuntime,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = (
    "prowler.providers.aws.services.bedrockagentcore."
    "bedrockagentcore_vpc_endpoints_configured."
    "bedrockagentcore_vpc_endpoints_configured"
)

AGENTCORE_SERVICES = [
    "com.amazonaws.us-east-1.bedrock-agentcore",
    "com.amazonaws.us-east-1.bedrock-agentcore-control",
    "com.amazonaws.us-east-1.bedrock-agentcore.gateway",
]

RUNTIME_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:"
    f"{AWS_ACCOUNT_NUMBER}:runtime/rt-1"
)


def _runtime(**kwargs) -> AgentCoreRuntime:
    values = dict(
        id="rt-1",
        name="rt",
        arn=RUNTIME_ARN,
        region=AWS_REGION_US_EAST_1,
        network_mode="VPC",
        subnets=[],
        detail_retrieved=True,
    )
    values.update(kwargs)
    return AgentCoreRuntime(**values)


def _agentcore_client(runtimes=None, scan_errors=None):
    return mock.MagicMock(
        agent_runtimes={runtime.arn: runtime for runtime in (runtimes or [])},
        agent_runtimes_scan_errors=scan_errors or {},
        audited_account=AWS_ACCOUNT_NUMBER,
        audited_partition="aws",
    )


def _create_vpc_and_subnet(ec2_client):
    vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2_client.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
    )["Subnet"]["SubnetId"]
    return vpc_id, subnet_id


def _create_endpoints(ec2_client, vpc_id, service_names):
    route_table = ec2_client.create_route_table(VpcId=vpc_id)["RouteTable"]
    for service_name in service_names:
        ec2_client.create_vpc_endpoint(
            VpcId=vpc_id,
            ServiceName=service_name,
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )


def _execute(aws_provider, vpc_service, agentcore_client):
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ):
        with (
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=vpc_service),
            mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=agentcore_client),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_vpc_endpoints_configured.bedrockagentcore_vpc_endpoints_configured import (
                bedrockagentcore_vpc_endpoints_configured,
            )

            return bedrockagentcore_vpc_endpoints_configured().execute()


class Test_bedrockagentcore_vpc_endpoints_configured:
    @mock_aws
    def test_no_runtimes(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(aws_provider, VPC(aws_provider), _agentcore_client())
        assert result == []

    @mock_aws
    def test_public_runtime_no_findings(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(network_mode="PUBLIC")]),
        )
        assert result == []

    @mock_aws
    def test_vpc_missing_all_endpoints(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].resource_id == vpc_id
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].status == "FAIL"
        assert "AgentCore data plane" in result[0].status_extended
        assert "AgentCore control plane" in result[0].status_extended
        assert "AgentCore gateway" in result[0].status_extended
        assert (
            result[0].resource_arn
            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc/{vpc_id}"
        )

    @mock_aws
    def test_vpc_all_endpoints(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        _create_endpoints(ec2_client, vpc_id, AGENTCORE_SERVICES)
        # A second VPC with no runtime should not be reported.
        _create_vpc_and_subnet(ec2_client)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].resource_id == vpc_id
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"VPC {vpc_id} has available VPC endpoints for all AgentCore services."
        )

    @mock_aws
    def test_vpc_missing_gateway_endpoint(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        _create_endpoints(
            ec2_client,
            vpc_id,
            [
                "com.amazonaws.us-east-1.bedrock-agentcore",
                "com.amazonaws.us-east-1.bedrock-agentcore-control",
            ],
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].resource_id == vpc_id
        assert result[0].status == "FAIL"
        assert "AgentCore gateway" in result[0].status_extended
        assert "AgentCore data plane" not in result[0].status_extended
        assert "AgentCore control plane" not in result[0].status_extended

    @mock_aws
    def test_gateway_endpoint_is_not_counted_as_data_plane(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        _create_endpoints(
            ec2_client,
            vpc_id,
            ["com.amazonaws.us-east-1.bedrock-agentcore.gateway"],
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AgentCore data plane" in result[0].status_extended
        assert "AgentCore control plane" in result[0].status_extended
        assert "AgentCore gateway" not in result[0].status_extended

    @mock_aws
    def test_unavailable_endpoint_does_not_count(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        _create_endpoints(ec2_client, vpc_id, AGENTCORE_SERVICES)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        vpc_service = VPC(aws_provider)
        for endpoint in vpc_service.vpc_endpoints:
            if endpoint.vpc_id == vpc_id and endpoint.service_name.endswith(
                ".bedrock-agentcore-control"
            ):
                endpoint.state = "pending"

        result = _execute(
            aws_provider,
            vpc_service,
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AgentCore control plane" in result[0].status_extended

    @mock_aws
    def test_list_runtimes_error_is_manual(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client(
                scan_errors={AWS_REGION_US_EAST_1: "AccessDeniedException"}
            ),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert "Could not list AgentCore runtimes" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended

    @mock_aws
    def test_unreadable_runtime_is_manual(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(detail_retrieved=False, network_mode=None)]),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "rt-1"
        assert "could not be described" in result[0].status_extended

    @mock_aws
    def test_vpc_runtime_with_unknown_subnet_is_manual(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(subnets=["subnet-missing"])]),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "rt-1"
        assert "subnets could not be resolved" in result[0].status_extended

    @mock_aws
    def test_missing_network_mode_is_manual(self):
        client("ec2", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client([_runtime(network_mode=None, detail_retrieved=True)]),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "rt-1"
        assert "has no network mode" in result[0].status_extended

    @mock_aws
    def test_resolved_subnet_without_vpc_inventory_is_manual(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        vpc_service = VPC(aws_provider)
        del vpc_service.vpcs[vpc_id]

        result = _execute(
            aws_provider,
            vpc_service,
            _agentcore_client([_runtime(subnets=[subnet_id])]),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "rt-1"
        assert "subnets could not be resolved" in result[0].status_extended

    @mock_aws
    def test_scan_error_does_not_pass_partial_inventory(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id, subnet_id = _create_vpc_and_subnet(ec2_client)
        _create_endpoints(ec2_client, vpc_id, AGENTCORE_SERVICES)
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _execute(
            aws_provider,
            VPC(aws_provider),
            _agentcore_client(
                [_runtime(subnets=[subnet_id])],
                scan_errors={AWS_REGION_US_EAST_1: "AccessDeniedException"},
            ),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "runtime/unknown"
        assert all(finding.status != "PASS" for finding in result)
