from importlib import import_module
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = (
    "prowler.providers.aws.services.elbv2."
    "elbv2_alb_drop_invalid_header_fields_enabled."
    "elbv2_alb_drop_invalid_header_fields_enabled"
)
ELBV2_CLIENT_PATCH = f"{CHECK_MODULE}.elbv2_client"
GLOBAL_PROVIDER_PATCH = ".".join(
    [
        "prowler.providers.common.provider.Provider",
        "get_global_provider",
    ]
)
PASS_STATUS_EXTENDED = " ".join(
    [
        "ELBv2 ALB my-lb is configured to drop invalid",
        "header fields.",
    ]
)
FAIL_STATUS_EXTENDED = (
    "ELBv2 ALB my-lb is not configured to drop invalid header fields."
)


def get_check_class():
    return getattr(
        import_module(CHECK_MODULE),
        "elbv2_alb_drop_invalid_header_fields_enabled",
    )


class Test_elbv2_alb_drop_invalid_header_fields_enabled:
    @mock_aws
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with (
            mock.patch(
                GLOBAL_PROVIDER_PATCH,
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
                ),
            ),
            mock.patch(
                ELBV2_CLIENT_PATCH,
                new=ELBv2(
                    set_mocked_aws_provider(
                        [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                        create_default_organization=False,
                    )
                ),
            ),
        ):
            check = get_check_class()()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elbv2_dropping_invalid_header_fields(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(
            CidrBlock="172.28.7.0/24",
            InstanceTenancy="default",
        )
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        conn.modify_load_balancer_attributes(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Attributes=[
                {
                    "Key": "routing.http.drop_invalid_header_fields.enabled",
                    "Value": "true",
                },
            ],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with (
            mock.patch(
                GLOBAL_PROVIDER_PATCH,
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
                ),
            ),
            mock.patch(
                ELBV2_CLIENT_PATCH,
                new=ELBv2(
                    set_mocked_aws_provider(
                        [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                        create_default_organization=False,
                    )
                ),
            ),
        ):
            check = get_check_class()()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == PASS_STATUS_EXTENDED
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_elbv2_not_dropping_invalid_header_fields(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(
            CidrBlock="172.28.7.0/24",
            InstanceTenancy="default",
        )
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        conn.modify_load_balancer_attributes(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Attributes=[
                {
                    "Key": "routing.http.drop_invalid_header_fields.enabled",
                    "Value": "false",
                },
            ],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with (
            mock.patch(
                GLOBAL_PROVIDER_PATCH,
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
                ),
            ),
            mock.patch(
                ELBV2_CLIENT_PATCH,
                new=ELBv2(
                    set_mocked_aws_provider(
                        [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                        create_default_organization=False,
                    )
                ),
            ),
        ):
            check = get_check_class()()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == FAIL_STATUS_EXTENDED
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_elbv2_network_load_balancer_ignored(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        vpc = ec2.create_vpc(
            CidrBlock="172.28.7.0/24",
            InstanceTenancy="default",
        )
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )

        conn.create_load_balancer(
            Name="my-nlb",
            Subnets=[subnet1.id],
            Scheme="internal",
            Type="network",
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with (
            mock.patch(
                GLOBAL_PROVIDER_PATCH,
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
                ),
            ),
            mock.patch(
                ELBV2_CLIENT_PATCH,
                new=ELBv2(
                    set_mocked_aws_provider(
                        [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                        create_default_organization=False,
                    )
                ),
            ),
        ):
            check = get_check_class()()
            result = check.execute()

            assert len(result) == 0
