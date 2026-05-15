from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_apigateway_restapi_no_secrets_in_stage_variables:
    @mock_aws
    def test_no_rest_apis(self):
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables.apigateway_client",
                new=APIGateway(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables import (
                apigateway_restapi_no_secrets_in_stage_variables,
            )

            check = apigateway_restapi_no_secrets_in_stage_variables()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_stage_with_no_variables(self):
        apigw = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        rest_api = apigw.create_rest_api(name="test-api")
        api_id = rest_api["id"]

        root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
        resource = apigw.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )
        apigw.put_method(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            type="HTTP",
            integrationHttpMethod="POST",
            uri="http://test.com",
        )
        apigw.create_deployment(restApiId=api_id, stageName="prod")

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables.apigateway_client",
                new=APIGateway(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables import (
                apigateway_restapi_no_secrets_in_stage_variables,
            )

            check = apigateway_restapi_no_secrets_in_stage_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "No secrets found in stage variables of API Gateway "
                "REST API test-api stage prod."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "test-api/prod"

    @mock_aws
    def test_stage_with_safe_variables(self):
        apigw = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        rest_api = apigw.create_rest_api(name="test-api")
        api_id = rest_api["id"]

        root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
        resource = apigw.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )
        apigw.put_method(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            type="HTTP",
            integrationHttpMethod="POST",
            uri="http://test.com",
        )
        apigw.create_deployment(restApiId=api_id, stageName="prod")
        apigw.update_stage(
            restApiId=api_id,
            stageName="prod",
            patchOperations=[
                {"op": "replace", "path": "/variables/environment", "value": "production"},
                {"op": "replace", "path": "/variables/region", "value": "us-east-1"},
            ],
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables.apigateway_client",
                new=APIGateway(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables import (
                apigateway_restapi_no_secrets_in_stage_variables,
            )

            check = apigateway_restapi_no_secrets_in_stage_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "No secrets found in stage variables of API Gateway "
                "REST API test-api stage prod."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "test-api/prod"

    @mock_aws
    def test_stage_with_secrets_in_variables(self):
        apigw = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        rest_api = apigw.create_rest_api(name="test-api")
        api_id = rest_api["id"]

        root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
        resource = apigw.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )
        apigw.put_method(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="GET",
            type="HTTP",
            integrationHttpMethod="POST",
            uri="http://test.com",
        )
        apigw.create_deployment(restApiId=api_id, stageName="prod")
        # AKIAIOSFODNN7EXAMPLE is a well-known fake AWS key that detect-secrets flags
        apigw.update_stage(
            restApiId=api_id,
            stageName="prod",
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/variables/aws_access_key",
                    "value": "AKIAIOSFODNN7EXAMPLE",
                },
            ],
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables.apigateway_client",
                new=APIGateway(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.apigateway.apigateway_restapi_no_secrets_in_stage_variables.apigateway_restapi_no_secrets_in_stage_variables import (
                apigateway_restapi_no_secrets_in_stage_variables,
            )

            check = apigateway_restapi_no_secrets_in_stage_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "test-api" in result[0].status_extended
            assert "prod" in result[0].status_extended
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "test-api/prod"