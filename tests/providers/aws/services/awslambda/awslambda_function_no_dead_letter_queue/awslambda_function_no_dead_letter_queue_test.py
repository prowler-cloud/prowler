from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.awslambda.awslambda_service import DeadLetterConfig
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

ROLE_POLICY = dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


class Test_awslambda_function_no_dead_letter_queue:
    def test_no_functions(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue import (
                awslambda_function_no_dead_letter_queue,
            )

            check = awslambda_function_no_dead_letter_queue()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_without_dlq(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=ROLE_POLICY,
        )["Role"]["Arn"]

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-function-no-dlq"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue import (
                awslambda_function_no_dead_letter_queue,
            )

            check = awslambda_function_no_dead_letter_queue()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert function_name in result[0].status_extended
            assert "Dead Letter Queue" in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_function_with_sqs_dlq(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=ROLE_POLICY,
        )["Role"]["Arn"]

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-function-with-dlq"
        queue_arn = f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:123456789012:test-dlq"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        lambda_service = Lambda(aws_provider)

        # moto does not return DeadLetterConfig in list_functions;
        # set it directly to test the PASS branch of the check logic.
        lambda_service.functions[function_arn].dead_letter_config = DeadLetterConfig(
            target_arn=queue_arn
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue.awslambda_client",
                new=lambda_service,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_no_dead_letter_queue.awslambda_function_no_dead_letter_queue import (
                awslambda_function_no_dead_letter_queue,
            )

            check = awslambda_function_no_dead_letter_queue()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert function_name in result[0].status_extended
            assert queue_arn in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
