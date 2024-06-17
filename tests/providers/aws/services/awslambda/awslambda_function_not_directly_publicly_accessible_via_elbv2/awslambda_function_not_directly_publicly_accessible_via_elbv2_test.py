from unittest import mock

from boto3 import client, resource
from mock import patch
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_provider,
)

from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
from prowler.providers.aws.services.awslambda.awslambda_service import Function
from prowler.providers.aws.services.ec2.ec2_service import EC2


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_awslambda_function_not_directly_publicly_accessible_via_elbv2:
    @mock_aws
    def test_no_functions_no_elbv2(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 0
    

    @mock_aws
    def test_no_function_with_public_elbv2_with_sg(self):
        # Lambda client
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group for load balancer"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_function_with_internal_elbv2_with_sg(self):
        # Lambda client
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_function_with_public_elbv2_without_sg(self):
        # Lambda client
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 0
    

    @mock_aws
    def test_no_function_with_public_elbv2_with_public_sg(self):
        # Lambda client
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_elbv2_internal(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Function

        # Lambda client
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "limited-access",
                    "Principal": {"AWS": [AWS_ACCOUNT_NUMBER]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="lambda",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": function_arn},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function '{function_name}' is not publicly accesible through an Internet facing Load Balancer."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == []

    @mock_aws
    def test_function_public_elbv2_and_public_lambda(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Lambda client
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"CanonicalUser": ["*"]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function (
                name=function_name,
                security_groups=[security_group.id],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        security_group2 = ec2.create_security_group(
            GroupName="sg02", Description="Second One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group2.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group2.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="lambda",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": function_arn},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function '{function_name}' is publicly accesible through an Internet facing Load Balancer '{lb["DNSName"]}'."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == []

    @mock_aws
    def test_function_public_elbv2_with_sg_and_internal_lambda(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                }
            ],
        )

        # Lambda client
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"AWS": [AWS_ACCOUNT_NUMBER]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function (
                name=function_name,
                security_groups=[security_group.id],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        security_group2 = ec2.create_security_group(
            GroupName="sg02", Description="Second One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group2.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                }
            ],
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group2.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="lambda",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": function_arn},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function '{function_name}' is not publicly accesible through an Internet facing Load Balancer."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == []

    
    @mock_aws
    def test_function_public_elbv2_with_sg_and_public_lambda(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Lambda client
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"CanonicalUser": ["*"]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function (
                name=function_name,
                security_groups=[security_group.id],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        security_group2 = ec2.create_security_group(
            GroupName="sg02", Description="Second One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group2.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                }
            ],
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group2.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="lambda",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": function_arn},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function '{function_name}' is not publicly accesible through an Internet facing Load Balancer."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == []

    @mock_aws
    def test_function_public_elbv2_public_sg_and_internal_lambda(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                }
            ],
        )

        security_group2 = ec2.create_security_group(
            GroupName="sg02", Description="Second One"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group2.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Lambda client
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"AWS": [AWS_ACCOUNT_NUMBER]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function (
                name=function_name,
                security_groups=[security_group.id],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_US_EAST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group2.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="lambda",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": function_arn},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_client",
            new=lambda_client,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_directly_publicly_accessible_via_elbv2.awslambda_function_not_directly_publicly_accessible_via_elbv2 import (
                awslambda_function_not_directly_publicly_accessible_via_elbv2,
            )

            check = awslambda_function_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function '{function_name}' is not publicly accesible through an Internet facing Load Balancer."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == []
    