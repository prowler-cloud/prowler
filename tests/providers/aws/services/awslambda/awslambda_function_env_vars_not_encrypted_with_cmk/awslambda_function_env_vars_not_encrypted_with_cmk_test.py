from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

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


class Test_awslambda_function_env_vars_not_encrypted_with_cmk:
    def test_no_functions(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk import (
                awslambda_function_env_vars_not_encrypted_with_cmk,
            )

            check = awslambda_function_env_vars_not_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_no_env_vars(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=ROLE_POLICY,
        )["Role"]["Arn"]

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-no-env"
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
                "prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk import (
                awslambda_function_env_vars_not_encrypted_with_cmk,
            )

            check = awslambda_function_env_vars_not_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no environment variables" in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_function_env_vars_no_kms(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=ROLE_POLICY,
        )["Role"]["Arn"]

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-env-no-kms"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
            Environment={"Variables": {"DB_HOST": "localhost"}},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk import (
                awslambda_function_env_vars_not_encrypted_with_cmk,
            )

            check = awslambda_function_env_vars_not_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "customer-managed KMS key" in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_function_env_vars_with_cmk(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=ROLE_POLICY,
        )["Role"]["Arn"]

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-env-with-kms"
        key_arn = (
            f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
        )
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
            Environment={"Variables": {"DB_HOST": "localhost"}},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        lambda_service = Lambda(aws_provider)

        # moto does not return KMSKeyArn in list_functions; inject it to test PASS branch.
        lambda_service.functions[function_arn].kms_key_arn = key_arn

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_client",
                new=lambda_service,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_env_vars_not_encrypted_with_cmk.awslambda_function_env_vars_not_encrypted_with_cmk import (
                awslambda_function_env_vars_not_encrypted_with_cmk,
            )

            check = awslambda_function_env_vars_not_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert key_arn in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
