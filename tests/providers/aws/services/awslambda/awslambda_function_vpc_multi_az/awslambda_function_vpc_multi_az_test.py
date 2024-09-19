from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    set_mocked_aws_provider,
)


class Test_awslambda_function_vpc_is_in_multi_azs:
    @mock_aws
    def test_no_functions(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_outside_vpc(self):
        # Create IAM Role for Lambda Function
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

        # Create Lambda Function outside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test_function_outside_vpc"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is not inside a VPC."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_function_in_vpc_single_az(self):
        # Create IAM Role for Lambda Function
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

        # Create VPC
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # Create Subnet
        subnet_id = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )["Subnet"]["SubnetId"]

        # Create Security Group
        security_group_id = ec2_client.create_security_group(
            GroupName="test-sg", Description="Test SG", VpcId=vpc_id
        )["GroupId"]

        # Create Lambda Function inside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)

        function_name = "test_function_in_vpc_single_az"

        function = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
            VpcConfig={
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [security_group_id],
            },
        )
        function_vpc_id = function["VpcConfig"]["VpcId"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is inside of VPC {function_vpc_id} that spans only in 1 AZs: {AWS_REGION_EU_WEST_1_AZA}. Must span in at least 2 AZs."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function["FunctionArn"]
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_function_in_vpc_multiple_az(self):
        # Create IAM Role for Lambda Function
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

        # Create VPC
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # Create Subnets
        subnet_id_a = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )["Subnet"]["SubnetId"]

        subnet_id_b = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )["Subnet"]["SubnetId"]

        # Create Security Group
        security_group_id = ec2_client.create_security_group(
            GroupName="test-sg", Description="Test SG", VpcId=vpc_id
        )["GroupId"]

        # Create Lambda Function inside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)

        function_name = "test_function_in_vpc_multiple_az"

        function = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
            VpcConfig={
                "SubnetIds": [subnet_id_a, subnet_id_b],
                "SecurityGroupIds": [security_group_id],
            },
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is inside of VPC {function['VpcConfig']['VpcId']} that spans in at least 2 AZs: {AWS_REGION_EU_WEST_1_AZB}, {AWS_REGION_EU_WEST_1_AZA}."
            ) or (
                result[0].status_extended
                == f"Lambda function {function_name} is inside of VPC {function['VpcConfig']['VpcId']} that spans in at least 2 AZs: {AWS_REGION_EU_WEST_1_AZA}, {AWS_REGION_EU_WEST_1_AZB}."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function["FunctionArn"]
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_function_with_multiple_subnets_in_same_az(self):
        # Create IAM Role for Lambda Function
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

        # Create VPC
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # Create Subnets
        subnet_id_a = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )["Subnet"]["SubnetId"]

        subnet_id_b = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )["Subnet"]["SubnetId"]

        # Create Security Group
        security_group_id = ec2_client.create_security_group(
            GroupName="test-sg", Description="Test SG", VpcId=vpc_id
        )["GroupId"]

        # Create Lambda Function inside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)

        function_name = "test_function_in_vpc_multiple_subnets_same_az"

        function = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
            VpcConfig={
                "SubnetIds": [subnet_id_a, subnet_id_b],
                "SecurityGroupIds": [security_group_id],
            },
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is inside of VPC {function['VpcConfig']['VpcId']} that spans only in 1 AZs: {AWS_REGION_EU_WEST_1_AZA}. Must span in at least 2 AZs."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function["FunctionArn"]
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_function_no_vpc_pass_to_avoid_fail_twice(self):
        # Create IAM Role for Lambda Function
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

        # Create Lambda Function outside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test_function_no_vpc_pass_to_avoid_fail_twice"
        lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.vpc_client",
            new=VPC(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test check inside_vpc first

            from prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc import (
                awslambda_function_inside_vpc,
            )

            check = awslambda_function_inside_vpc()

            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

            # Now test if function is in multiple AZs to ensure it does not fail twice

            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_resource_filtered(self):
        # Create a compliant Lambda Function

        # Create IAM Role for Lambda Function
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

        # Create VPC
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # Create Subnets
        subnet_id_a = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )["Subnet"]["SubnetId"]

        subnet_id_b = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )["Subnet"]["SubnetId"]

        # Create Security Group
        security_group_id = ec2_client.create_security_group(
            GroupName="test-sg", Description="Test SG", VpcId=vpc_id
        )["GroupId"]

        # Create Lambda Function inside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)

        function_name = "test_function_resource_filtered"

        function = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
            VpcConfig={
                "SubnetIds": [subnet_id_a, subnet_id_b],
                "SecurityGroupIds": [security_group_id],
            },
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Filter the resource in the provider, this is like the --resource-arn option
        aws_provider._audit_resources = [function["FunctionArn"]]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.awslambda_client",
            new=Lambda(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_vpc_multi_az.awslambda_function_vpc_multi_az import (
                awslambda_function_vpc_multi_az,
            )

            check = awslambda_function_vpc_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].status == "FAIL"
            )  # This should be a PASS, but the resource is filtered so subnets are filtered and this is a bug
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is inside of VPC {function['VpcConfig']['VpcId']} that spans only in 0 AZs: . Must span in at least 2 AZs."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function["FunctionArn"]
            assert result[0].resource_tags == [{}]
