from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.awslambda.awslambda_service import Function
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_awslambda_function_not_publicly_accessible:
    @mock_aws
    def test_no_functions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_public(self):
        # Create the mock IAM role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        function_name = "test-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="nodejs4.3",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a wildcard principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal="*",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    @mock_aws
    def test_function_public_with_source_account(self):
        # Create the mock IAM role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        function_name = "test-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="nodejs4.3",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a wildcard principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="non-public-access",
            Action="lambda:InvokeFunction",
            Principal="*",
            SourceArn=function_arn,
            SourceAccount=AWS_ACCOUNT_NUMBER,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    @mock_aws
    def test_function_not_public(self):
        # Create the mock IAM role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        function_name = "test-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="nodejs4.3",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a specific AWS account number as principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal=AWS_ACCOUNT_NUMBER,
            SourceArn=function_arn,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    def test_function_public_with_canonical(self):
        lambda_client = mock.MagicMock
        lambda_client.audited_account = AWS_ACCOUNT_NUMBER
        lambda_client.audit_config = {}
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
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
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_EU_WEST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_function_public_with_alb(self):
        # Create the mock VPC
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        # Create subnets
        subnet_a = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )
        subnet_b = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
        )

        # Create an Internet Gateway
        igw = ec2_client.create_internet_gateway()
        igw_id = igw["InternetGateway"]["InternetGatewayId"]
        ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

        # Create a Route Table and associate it with subnets
        route_table = ec2_client.create_route_table(VpcId=vpc_id)
        route_table_id = route_table["RouteTable"]["RouteTableId"]
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw_id,
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_id, SubnetId=subnet_a["Subnet"]["SubnetId"]
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_id, SubnetId=subnet_b["Subnet"]["SubnetId"]
        )

        # Create the mock IAM role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        function_name = "test-public-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a wildcard principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal="*",
        )

        # Create a security group for ALB
        sg = ec2_client.create_security_group(
            GroupName="alb-sg",
            Description="Security group for ALB",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Create the ALB
        elbv2_client = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        lb = elbv2_client.create_load_balancer(
            Name="test-alb",
            Subnets=[subnet_a["Subnet"]["SubnetId"], subnet_b["Subnet"]["SubnetId"]],
            SecurityGroups=[sg_id],
            Scheme="internet-facing",
            Type="application",
            IpAddressType="ipv4",
        )
        lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]

        # Create the Target Group for Lambda
        target_group = elbv2_client.create_target_group(
            Name="test-public-lambda-tg",
            TargetType="lambda",
        )
        target_group_arn = target_group["TargetGroups"][0]["TargetGroupArn"]

        # Add permission for ALB to invoke the Lambda function
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="alb-access",
            Action="lambda:InvokeFunction",
            Principal="elasticloadbalancing.amazonaws.com",
            SourceArn=target_group_arn,
        )

        # Attach Lambda to Target Group
        elbv2_client.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[{"Id": function_arn}],
        )

        # Create ALB Listener
        elbv2_client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Lambda function test-public-lambda has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    def test_function_could_be_invoked_by_specific_aws_account(self):
        lambda_client = mock.MagicMock
        lambda_client.audited_account = AWS_ACCOUNT_NUMBER
        lambda_client.audit_config = {}
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "awslambda-myLambdaScript-LambdaInvokePermission",
                    "Effect": "Allow",
                    "Principal": {"Service": "ses.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function:{function_name}",
                    "Condition": {
                        "StringEquals": {"AWS:SourceAccount": AWS_ACCOUNT_NUMBER}
                    },
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_EU_WEST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=lambda_client,
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == []

    def test_function_could_be_invoked_by_specific_other_aws_account(self):
        lambda_client = mock.MagicMock
        lambda_client.audited_account = AWS_ACCOUNT_NUMBER
        lambda_client.audit_config = {}
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "awslambda-myLambdaScript-LambdaInvokePermission",
                    "Effect": "Allow",
                    "Principal": {"Service": "ses.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function:{function_name}",
                    "Condition": {
                        "StringEquals": {"AWS:SourceAccount": "000000000000"}
                    },
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_EU_WEST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=lambda_client,
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == []

    def test_function_public_policy_with_several_statements(self):
        lambda_client = mock.MagicMock
        lambda_client.audited_account = AWS_ACCOUNT_NUMBER
        lambda_client.audit_config = {}
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "AllowExecutionFromAPIGateway",
                    "Effect": "Allow",
                    "Principal": {"Service": "apigateway.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:eu-central-1:{AWS_ACCOUNT_NUMBER}:function:foo",
                    "Condition": {
                        "ArnLike": {
                            "AWS:SourceArn": f"arn:aws:execute-api:eu-central-1:{AWS_ACCOUNT_NUMBER}:bar/*/GET/proxy+"
                        }
                    },
                },
                {
                    "Sid": "FunctionURLAllowPublicAccess",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "lambda:InvokeFunctionUrl",
                    "Resource": f"arn:aws:lambda:eu-central-1:{AWS_ACCOUNT_NUMBER}:function:foo",
                    "Condition": {
                        "StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}
                    },
                },
            ],
        }

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_EU_WEST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=lambda_client,
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
