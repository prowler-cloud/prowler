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
EXTERNAL_ACCOUNT = "999999999999"


def _create_role(iam_client):
    return iam_client.create_role(
        RoleName="test-role",
        AssumeRolePolicyDocument=ROLE_POLICY,
    )["Role"]["Arn"]


class Test_awslambda_function_using_cross_account_layers:
    def test_no_functions(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers import (
                awslambda_function_using_cross_account_layers,
            )

            check = awslambda_function_using_cross_account_layers()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_no_layers(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = _create_role(iam_client)

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-no-layers"
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
                "prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers.awslambda_client",
                new=Lambda(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers import (
                awslambda_function_using_cross_account_layers,
            )

            check = awslambda_function_using_cross_account_layers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not use any layers" in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn

    @mock_aws
    def test_function_own_account_layer(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = _create_role(iam_client)

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-own-layer"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import (
            Lambda,
            Layer,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        lambda_service = Lambda(aws_provider)

        # moto does not return Layers in list_functions; inject an own-account layer.
        own_layer_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:layer:my-layer:1"
        lambda_service.functions[function_arn].layers = [Layer(arn=own_layer_arn)]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers.awslambda_client",
                new=lambda_service,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers import (
                awslambda_function_using_cross_account_layers,
            )

            check = awslambda_function_using_cross_account_layers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert AWS_ACCOUNT_NUMBER in result[0].status_extended

    @mock_aws
    def test_function_cross_account_layer(self):
        """Function uses a layer from an external account — FAIL."""
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_arn = _create_role(iam_client)

        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test-fn-cross-layer"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import (
            Lambda,
            Layer,
        )

        cross_layer_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{EXTERNAL_ACCOUNT}:layer:ext-layer:1"
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        lambda_service = Lambda(aws_provider)

        # moto does not return Layers; inject a cross-account layer to test FAIL branch.
        lambda_service.functions[function_arn].layers = [Layer(arn=cross_layer_arn)]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers.awslambda_client",
                new=lambda_service,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_using_cross_account_layers.awslambda_function_using_cross_account_layers import (
                awslambda_function_using_cross_account_layers,
            )

            check = awslambda_function_using_cross_account_layers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert cross_layer_arn in result[0].status_extended
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
