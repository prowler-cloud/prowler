from re import search
from unittest import mock

import botocore
from boto3 import client, resource
from moto import mock_ec2, mock_elbv2, mock_wafv2

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Mocking WAF-Regional Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": "my-web-acl-id", "Name": "my-web-acl"},
            ]
        }
    if operation_name == "ListResourcesForWebACL":
        return {
            "ResourceArns": [
                "alb-arn",
            ]
        }

    return make_api_call(self, operation_name, kwarg)


class Test_elbv2_waf_acl_attached:
    @mock_wafv2
    @mock_elbv2
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.waf.waf_service import WAF
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.wafv2_client",
            new=WAFv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.waf_client",
            new=WAF(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached import (
                elbv2_waf_acl_attached,
            )

            check = elbv2_waf_acl_attached()
            result = check.execute()

            assert len(result) == 0

    @mock_wafv2
    @mock_ec2
    @mock_elbv2
    def test_elbv2_without_WAF(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        wafv2 = client("wafv2", region_name="us-east-1")
        _ = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
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

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.waf.waf_service import WAF
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.wafv2_client",
            new=WAFv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.waf_client",
            new=WAF(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached import (
                elbv2_waf_acl_attached,
            )

            check = elbv2_waf_acl_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is not protected by WAF Web ACL",
                result[0].status_extended,
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_wafv2
    @mock_ec2
    @mock_elbv2
    def test_elbv2_with_WAF(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        wafv2 = client("wafv2", region_name="us-east-1")
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
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

        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=lb["LoadBalancerArn"])

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.waf.waf_service import WAF
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.elbv2_client",
            new=ELBv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.wafv2_client",
            new=WAFv2(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
        ) as service_client:
            with mock.patch(
                "prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached.waf_client",
                new=WAF(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])),
            ):
                # Test Check
                from prowler.providers.aws.services.elbv2.elbv2_waf_acl_attached.elbv2_waf_acl_attached import (
                    elbv2_waf_acl_attached,
                )

                service_client.web_acls[0].albs.append(lb["LoadBalancerArn"])

                check = elbv2_waf_acl_attached()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "is protected by WAFv2 Web ACL",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "my-lb"
                assert result[0].resource_arn == lb["LoadBalancerArn"]
