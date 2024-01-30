from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.shield.shield_service import Protection
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_shield_advanced_protection_in_classic_load_balancers:
    @mock_aws
    @mock_aws
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock_aws
    def test_shield_enabled_elb_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )
        elb_name = "my-lb"
        elb.create_load_balancer(
            LoadBalancerName=elb_name,
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION_EU_WEST_1}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=elb_arn,
                protection_arn="",
                region=AWS_REGION_EU_WEST_1,
            )
        }

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is protected by AWS Shield Advanced."
            )

    @mock_aws
    @mock_aws
    def test_shield_enabled_elb_not_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )
        elb_name = "my-lb"
        elb.create_load_balancer(
            LoadBalancerName=elb_name,
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION_EU_WEST_1}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is not protected by AWS Shield Advanced."
            )

    @mock_aws
    @mock_aws
    def test_shield_disabled_elb_not_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )
        elb_name = "my-lb"
        elb.create_load_balancer(
            LoadBalancerName=elb_name,
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION_EU_WEST_1}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        _ = f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0
