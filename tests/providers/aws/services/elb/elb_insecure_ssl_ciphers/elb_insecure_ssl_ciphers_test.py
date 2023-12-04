from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2, mock_elb

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
elb_arn = (
    f"arn:aws:elasticloadbalancing:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
)


class Test_elb_insecure_ssl_ciphers:
    @mock_elb
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
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
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            from prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers import (
                elb_insecure_ssl_ciphers,
            )

            check = elb_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not have insecure SSL protocols or ciphers",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn

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
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_insecure_ssl_ciphers.elb_insecure_ssl_ciphers.elb_client",
            new=ELB(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
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
            assert result[0].resource_arn == elb_arn
