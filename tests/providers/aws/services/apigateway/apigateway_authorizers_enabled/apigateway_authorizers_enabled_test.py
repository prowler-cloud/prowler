from unittest import mock

from boto3 import client
from moto import mock_apigateway, mock_iam, mock_lambda

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_apigateway_restapi_authorizers_enabled:
    @mock_apigateway
    def test_apigateway_no_rest_apis(self):
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled import (
                apigateway_restapi_authorizers_enabled,
            )

            check = apigateway_restapi_authorizers_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    @mock_iam
    @mock_lambda
    def test_apigateway_one_rest_api_with_lambda_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        lambda_client = client("lambda", region_name=AWS_REGION_US_EAST_1)
        iam_client = client("iam")
        # Create APIGateway Rest API
        role_arn = iam_client.create_role(
            RoleName="my-role",
            AssumeRolePolicyDocument="some policy",
        )["Role"]["Arn"]
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        authorizer = lambda_client.create_function(
            FunctionName="lambda-authorizer",
            Runtime="python3.7",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={
                "ImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/hello-world:latest"
            },
        )
        apigateway_client.create_authorizer(
            name="test",
            restApiId=rest_api["id"],
            type="TOKEN",
            authorizerUri=f"arn:aws:apigateway:{apigateway_client.meta.region_name}:lambda:path/2015-03-31/functions/arn:aws:lambda:{apigateway_client.meta.region_name}:{AWS_ACCOUNT_NUMBER}:function:{authorizer['FunctionName']}/invocations",
        )
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled import (
                apigateway_restapi_authorizers_enabled,
            )

            check = apigateway_restapi_authorizers_enabled()
            result = check.execute()

            assert result[0].status == "PASS"
            assert len(result) == 1
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} has an authorizer configured."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_apigateway
    def test_apigateway_one_rest_api_without_lambda_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        # Create APIGateway Rest API
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled import (
                apigateway_restapi_authorizers_enabled,
            )

            check = apigateway_restapi_authorizers_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert len(result) == 1
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have an authorizer configured."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]
