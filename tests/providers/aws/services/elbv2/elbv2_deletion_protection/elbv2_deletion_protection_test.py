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


class Test_elbv2_deletion_protection:
    @mock_aws
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection.elbv2_client",
            new=ELBv2(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection import (
                elbv2_deletion_protection,
            )

            check = elbv2_deletion_protection()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elbv2_without_deletion_protection(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
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
                {"Key": "deletion_protection.enabled", "Value": "false"},
            ],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection.elbv2_client",
            new=ELBv2(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection import (
                elbv2_deletion_protection,
            )

            check = elbv2_deletion_protection()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELBv2 my-lb does not have deletion protection enabled."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_elbv2_with_deletion_protection(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
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
        )["LoadBalancers"][0]

        conn.modify_load_balancer_attributes(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Attributes=[
                {"Key": "deletion_protection.enabled", "Value": "true"},
            ],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection.elbv2_client",
            new=ELBv2(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_deletion_protection.elbv2_deletion_protection import (
                elbv2_deletion_protection,
            )

            check = elbv2_deletion_protection()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELBv2 my-lb has deletion protection enabled."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]
