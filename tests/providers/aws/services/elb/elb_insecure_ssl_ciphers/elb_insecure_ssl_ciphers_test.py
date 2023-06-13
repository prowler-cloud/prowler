from re import search
from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2, mock_elb

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_elb_insecure_ssl_ciphers:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )

        return audit_info

    @mock_elb
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers import (
                elb_insecure_ssl_ciphers,
            )

            check = elb_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elb
    def test_elb_listener_with_secure_policy(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "https", "LoadBalancerPort": 443, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION}a"],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        elb.set_load_balancer_policies_of_listener(
            LoadBalancerName="my-lb",
            LoadBalancerPort=443,
            PolicyNames=["ELBSecurityPolicy-TLS-1-2-2017-01"],
        )
        elb.describe_load_balancer_policies(LoadBalancerName="my-lb")

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            from prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers import (
                elb_insecure_ssl_ciphers,
            )

            check = elb_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has not insecure SSL protocols or ciphers",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"

    @mock_ec2
    @mock_elb
    def test_elb_with_HTTPS_listener(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "https", "LoadBalancerPort": 443, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION}a"],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(self.set_mocked_audit_info()),
        ):
            from prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers import (
                elb_insecure_ssl_ciphers,
            )

            check = elb_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has listeners with insecure SSL protocols or ciphers",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
