from re import search
from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2, mock_elbv2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_elbv2_ssl_listeners:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
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
        )

        return audit_info

    @mock_elbv2
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners.elbv2_client",
            new=ELBv2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners import (
                elbv2_ssl_listeners,
            )

            check = elbv2_ssl_listeners()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    @mock_elbv2
    def test_elbv2_with_HTTP_listener(self):
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
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )
        target_group = response.get("TargetGroups")[0]
        target_group_arn = target_group["TargetGroupArn"]
        response = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners.elbv2_client",
            new=ELBv2(self.set_mocked_audit_info()),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners import (
                elbv2_ssl_listeners,
            )

            check = elbv2_ssl_listeners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has non-encrypted listeners",
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
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )
        target_group = response.get("TargetGroups")[0]
        target_group_arn = target_group["TargetGroupArn"]
        response = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners.elbv2_client",
            new=ELBv2(self.set_mocked_audit_info()),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners import (
                elbv2_ssl_listeners,
            )

            check = elbv2_ssl_listeners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has HTTPS listeners only",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_ec2
    @mock_elbv2
    def test_elbv2_with_HTTPS_redirection(self):
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

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[
                {
                    "Type": "redirect",
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                        "Port": "443",
                        "StatusCode": "HTTP_301",
                    },
                }
            ],
        )

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners.elbv2_client",
            new=ELBv2(self.set_mocked_audit_info()),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_ssl_listeners.elbv2_ssl_listeners import (
                elbv2_ssl_listeners,
            )

            check = elbv2_ssl_listeners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has HTTP listener but it redirects to HTTPS",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]
