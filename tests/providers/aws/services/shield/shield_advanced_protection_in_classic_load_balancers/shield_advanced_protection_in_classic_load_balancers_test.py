from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2, mock_elb
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.shield.shield_service import Protection

AWS_REGION = "eu-west-1"


class Test_shield_advanced_protection_in_classic_load_balancers:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=DEFAULT_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        return audit_info

    @mock_elb
    @mock_ec2
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
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elb
    def test_shield_enabled_elb_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

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
            AvailabilityZones=[f"{AWS_REGION}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=elb_arn,
                protection_arn="",
                region=AWS_REGION,
            )
        }

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is protected by AWS Shield Advanced"
            )

    @mock_elb
    @mock_ec2
    def test_shield_enabled_elb_not_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

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
            AvailabilityZones=[f"{AWS_REGION}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is not protected by AWS Shield Advanced"
            )

    @mock_elb
    @mock_ec2
    def test_shield_disabled_elb_not_protected(self):
        # ELB Client
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

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
            AvailabilityZones=[f"{AWS_REGION}a"],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )
        _ = f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0
