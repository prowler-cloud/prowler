from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.elbv2.elbv2_listener_fips_tls_enabled.elbv2_listener_fips_tls_enabled"
FIPS_POLICY = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
NON_FIPS_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"


def create_application_load_balancer():
    conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
    ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
    security_group = ec2.create_security_group(
        GroupName="a-security-group", Description="First One"
    )
    vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
    subnet1 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock="172.28.7.192/26",
        AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
    )
    subnet2 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock="172.28.7.0/26",
        AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
    )
    lb = conn.create_load_balancer(
        Name="my-lb",
        Subnets=[subnet1.id, subnet2.id],
        SecurityGroups=[security_group.id],
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]
    target_group_arn = conn.create_target_group(
        Name="a-target", Protocol="HTTP", Port=8080, VpcId=vpc.id
    )["TargetGroups"][0]["TargetGroupArn"]
    return conn, lb, target_group_arn


def create_listener(conn, lb, target_group_arn, protocol, port, ssl_policy=None):
    listener_args = {
        "LoadBalancerArn": lb["LoadBalancerArn"],
        "Protocol": protocol,
        "Port": port,
        "DefaultActions": [{"Type": "forward", "TargetGroupArn": target_group_arn}],
    }
    if ssl_policy:
        listener_args["SslPolicy"] = ssl_policy
    return conn.create_listener(**listener_args)["Listeners"][0]


def execute_check(service=None):
    from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        create_default_organization=False,
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.elbv2_client", new=service or ELBv2(aws_provider)),
    ):
        from prowler.providers.aws.services.elbv2.elbv2_listener_fips_tls_enabled.elbv2_listener_fips_tls_enabled import (
            elbv2_listener_fips_tls_enabled,
        )

        return elbv2_listener_fips_tls_enabled().execute()


class Test_elbv2_listener_fips_tls_enabled:
    @mock_aws
    def test_no_load_balancers(self):
        assert execute_check() == []

    @mock_aws
    def test_http_listener_only(self):
        conn, lb, target_group_arn = create_application_load_balancer()
        create_listener(conn, lb, target_group_arn, "HTTP", 80)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == "ELBv2 my-lb has no HTTPS/TLS listeners."

    @mock_aws
    def test_fips_policy(self):
        conn, lb, target_group_arn = create_application_load_balancer()
        create_listener(conn, lb, target_group_arn, "HTTPS", 443, FIPS_POLICY)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has all HTTPS/TLS listeners using a FIPS TLS security policy."
        )
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_non_fips_policy(self):
        conn, lb, target_group_arn = create_application_load_balancer()
        listener = create_listener(
            conn, lb, target_group_arn, "HTTPS", 443, NON_FIPS_POLICY
        )

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"ELBv2 my-lb has HTTPS/TLS listeners without a FIPS TLS security policy: HTTPS:443 ({listener['ListenerArn']}) uses {NON_FIPS_POLICY}."
        )

    @mock_aws
    def test_mixed_listeners(self):
        conn, lb, target_group_arn = create_application_load_balancer()
        create_listener(conn, lb, target_group_arn, "HTTPS", 443, FIPS_POLICY)
        create_listener(conn, lb, target_group_arn, "HTTPS", 8443, NON_FIPS_POLICY)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert NON_FIPS_POLICY in result[0].status_extended
        assert FIPS_POLICY not in result[0].status_extended

    @mock_aws
    def test_listener_discovery_failed(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        conn, lb, target_group_arn = create_application_load_balancer()
        create_listener(conn, lb, target_group_arn, "HTTPS", 443, NON_FIPS_POLICY)
        service = ELBv2(
            set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                create_default_organization=False,
            )
        )
        service.loadbalancersv2[lb["LoadBalancerArn"]].listener_discovery_failed = True

        assert execute_check(service) == []
