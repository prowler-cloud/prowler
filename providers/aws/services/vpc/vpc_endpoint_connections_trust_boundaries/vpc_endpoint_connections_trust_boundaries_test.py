import json
from unittest import mock

from boto3 import client
from moto import mock_ec2

AWS_REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


def mock_get_config_var(config_var):
    if config_var == "trusted_account_ids":
        return ["123456789010"]
    return []


class Test_vpc_endpoint_connections_trust_boundaries:
    @mock_ec2
    def test_vpc_no_endpoints(self):
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                vpc_endpoint_connections_trust_boundaries,
            )

            check = vpc_endpoint_connections_trust_boundaries()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_vpc_endpoint_with_full_access(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Action": "*",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                vpc_endpoint_connections_trust_boundaries,
            )

            check = vpc_endpoint_connections_trust_boundaries()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VPC Endpoint {vpc_endpoint['VpcEndpoint']['VpcEndpointId']} in VPC {vpc['VpcId']} has full access."
            )
            assert result[0].resource_id == vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]
            assert result[0].region == AWS_REGION

    @mock_ec2
    def test_vpc_endpoint_with_trusted_account(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_account = ACCOUNT_ID

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                vpc_endpoint_connections_trust_boundaries,
            )

            check = vpc_endpoint_connections_trust_boundaries()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Found trusted account {ACCOUNT_ID} in VPC Endpoint {vpc_endpoint['VpcEndpoint']['VpcEndpointId']} in VPC {vpc['VpcId']}."
            )
            assert result[0].resource_id == vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]
            assert result[0].region == AWS_REGION

    @mock_ec2
    def test_vpc_endpoint_with_untrusted_account(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789010:root"},
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_account = ACCOUNT_ID

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                vpc_endpoint_connections_trust_boundaries,
            )

            check = vpc_endpoint_connections_trust_boundaries()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Found untrusted account 123456789010 in VPC Endpoint {vpc_endpoint['VpcEndpoint']['VpcEndpointId']} in VPC {vpc['VpcId']}."
            )
            assert result[0].resource_id == vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]

    @mock_ec2
    def test_vpc_endpoint_with_config_trusted_account(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789010:root"},
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.vpc.vpc_service import VPC

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_account = ACCOUNT_ID

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=VPC(current_audit_info),
        ):
            with mock.patch(
                "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.get_config_var",
                new=mock_get_config_var,
            ):
                # Test Check
                from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                    vpc_endpoint_connections_trust_boundaries,
                )

                check = vpc_endpoint_connections_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Found trusted account 123456789010 in VPC Endpoint {vpc_endpoint['VpcEndpoint']['VpcEndpointId']} in VPC {vpc['VpcId']}."
                )
                assert (
                    result[0].resource_id
                    == vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]
                )
                assert result[0].region == AWS_REGION

    @mock_ec2
    def test_bad_response(self):
        mock_client = mock.MagicMock()

        with mock.patch(
            "providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries.vpc_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.vpc.vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import (
                vpc_endpoint_connections_trust_boundaries,
            )

            check = vpc_endpoint_connections_trust_boundaries()
            result = check.execute()

            assert len(result) == 0
