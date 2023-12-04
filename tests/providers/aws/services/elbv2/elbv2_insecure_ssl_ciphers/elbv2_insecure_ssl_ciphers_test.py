from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2, mock_elbv2

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_elbv2_insecure_ssl_ciphers:
    @mock_elbv2
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers import (
                elbv2_insecure_ssl_ciphers,
            )

            check = elbv2_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elbv2
    def test_elbv2_listener_with_secure_policy(self):
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

        response = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=8080,
            VpcId=vpc.id,
            HealthCheckProtocol="HTTP",
            HealthCheckPort="8080",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=5,
            HealthCheckTimeoutSeconds=3,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )
        target_group = response.get("TargetGroups")[0]
        target_group_arn = target_group["TargetGroupArn"]
        response = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS-1-2-2017-01",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers import (
                elbv2_insecure_ssl_ciphers,
            )

            check = elbv2_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not have insecure SSL protocols or ciphers",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_ec2
    @mock_elbv2
    def test_elbv2_with_HTTPS_listener(self):
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
        )["LoadBalancers"][0]

        response = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=8080,
            VpcId=vpc.id,
            HealthCheckProtocol="HTTP",
            HealthCheckPort="8080",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=5,
            HealthCheckTimeoutSeconds=3,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )
        target_group = response.get("TargetGroups")[0]
        target_group_arn = target_group["TargetGroupArn"]
        response = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            SslPolicy="ELBSecurityPolicy-TLS-1-1-2017-01",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers import (
                elbv2_insecure_ssl_ciphers,
            )

            check = elbv2_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has listeners with insecure SSL protocols or ciphers",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]
