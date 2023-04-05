from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2, mock_elbv2

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_elbv2_internet_facing:
    @mock_elbv2
    def test_elb_no_balancers(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing.elbv2_client",
            new=ELBv2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing import (
                elbv2_internet_facing,
            )

            check = elbv2_internet_facing()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elbv2
    def test_elbv2_private(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing.elbv2_client",
            new=ELBv2(current_audit_info),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing import (
                elbv2_internet_facing,
            )

            check = elbv2_internet_facing()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "is not internet facing",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_ec2
    @mock_elbv2
    def test_elbv2_with_deletion_protection(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
        )["LoadBalancers"][0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing.elbv2_client",
            new=ELBv2(current_audit_info),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_internet_facing.elbv2_internet_facing import (
                elbv2_internet_facing,
            )

            check = elbv2_internet_facing()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is internet facing",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]
