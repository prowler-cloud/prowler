from unittest import mock

import botocore
from boto3 import client
from mock import patch
from moto import mock_ec2, mock_elbv2

AWS_REGION = "us-east-1"
ACCOUNT_ID = "123456789012"

# Mocking VPC Calls
make_api_call = botocore.client.BaseClient._make_api_call
# Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
#
# We have to mock every AWS API call using Boto3
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeVpcEndpointServices":
        return {
            "ServiceDetails": [
                {
                    "ServiceId": "vpce-svc-4b919ac5",
                    "ServiceName": "string",
                    "Owner": ACCOUNT_ID,
                    "StageName": "test-stage",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_vpc_endpoint_services_allowed_principals_trust_boundaries:
    @mock_ec2
    def test_vpc_no_endpoint_services(self):
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                vpc_endpoint_services_allowed_principals_trust_boundaries,
            )

            check = vpc_endpoint_services_allowed_principals_trust_boundaries()
            result = check.execute()

            assert len(result) == 23  # one endpoint per region

    @mock_ec2
    @mock_elbv2
    def test_vpc_endpoint_service_without_allowed_principals(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        elbv2_client = client("elbv2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        # Service is mocked until moto fix the issue https://github.com/spulec/moto/issues/5605
        # service = ec2_client.create_vpc_endpoint_service_configuration(
        #     NetworkLoadBalancerArns=[lb_arn]
        # )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                vpc_endpoint_services_allowed_principals_trust_boundaries,
            )

            check = vpc_endpoint_services_allowed_principals_trust_boundaries()
            result = check.execute()

            assert len(result) == 23  # one per region
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"VPC Endpoint Service {ec2_client.describe_vpc_endpoint_services()['ServiceDetails'][0]['ServiceId']} has no allowed principals."
            )
            assert (
                result[0].resource_id
                == ec2_client.describe_vpc_endpoint_services()["ServiceDetails"][0][
                    "ServiceId"
                ]
            )
