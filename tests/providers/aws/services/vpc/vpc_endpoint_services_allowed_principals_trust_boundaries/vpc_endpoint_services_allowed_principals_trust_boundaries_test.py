from unittest import mock

import botocore
from boto3 import client, session
from mock import patch
from moto import mock_ec2, mock_elbv2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Mocking VPC Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    We have to mock every AWS API call using Boto3

    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "DescribeVpcEndpointServices":
        return {
            "ServiceDetails": [
                {
                    "ServiceId": "vpce-svc-4b919ac5",
                    "ServiceName": "string",
                    "Owner": AWS_ACCOUNT_NUMBER,
                    "StageName": "test-stage",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_vpc_endpoint_services_allowed_principals_trust_boundaries:
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
            audited_regions=[AWS_REGION],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_ec2
    def test_vpc_no_endpoint_services(self):
        # VPC Endpoint Services
        ec2_client = client("ec2", region_name=AWS_REGION)
        endpoint_id = ec2_client.describe_vpc_endpoint_services()["ServiceDetails"][0][
            "ServiceId"
        ]
        endpoint_arn = f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()
        # Set config variable
        current_audit_info.audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1  # one endpoint per region
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Endpoint Service {endpoint_id} has no allowed principals."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags is None
                assert result[0].region == AWS_REGION

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

        _ = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )

        endpoint_id = ec2_client.describe_vpc_endpoint_services()["ServiceDetails"][0][
            "ServiceId"
        ]
        endpoint_arn = f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()
        # Set config variable
        current_audit_info.audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Endpoint Service {ec2_client.describe_vpc_endpoint_services()['ServiceDetails'][0]['ServiceId']} has no allowed principals."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags is None
                assert result[0].region == AWS_REGION
