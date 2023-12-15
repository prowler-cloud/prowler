from unittest import mock

from boto3 import client, resource
from mock import patch
from moto import mock_ec2, mock_elbv2

from prowler.providers.aws.services.shield.shield_service import Protection
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_shield_advanced_protection_in_internet_facing_load_balancers:
    @mock_ec2
    @mock_elbv2
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elbv2
    def test_shield_enabled_elbv2_internet_facing_protected(self):
        # ELBv2 Client
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
        lb_name = "my-lb"
        lb = conn.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]
        lb_arn = lb["LoadBalancerArn"]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=lb_arn,
                protection_arn="",
                region=AWS_REGION_EU_WEST_1,
            )
        }

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == lb_name
            assert result[0].resource_arn == lb["LoadBalancerArn"]
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELBv2 ALB {lb_name} is protected by AWS Shield Advanced."
            )

    @mock_ec2
    @mock_elbv2
    def test_shield_enabled_elbv2_internal_protected(self):
        # ELBv2 Client
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
        lb_name = "my-lb"
        lb = conn.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]
        lb_arn = lb["LoadBalancerArn"]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=lb_arn,
                protection_arn="",
                region=AWS_REGION_EU_WEST_1,
            )
        }

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elbv2
    def test_shield_enabled_elbv2_internet_facing_not_protected(self):
        # ELBv2 Client
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
        lb_name = "my-lb"
        lb = conn.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]
        lb_arn = lb["LoadBalancerArn"]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == lb_name
            assert result[0].resource_arn == lb_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELBv2 ALB {lb_name} is not protected by AWS Shield Advanced."
            )

    @mock_ec2
    @mock_elbv2
    def test_shield_disabled_elbv2_internet_facing_not_protected(self):
        # ELBv2 Client
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
        lb_name = "my-lb"
        lb = conn.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]
        _ = lb["LoadBalancerArn"]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0
