from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_apigateway_restapi_authorizers_enabled:
    @mock_aws
    def test_apigateway_no_rest_apis(self):
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled import (
                apigateway_restapi_authorizers_enabled,
            )

            check = apigateway_restapi_authorizers_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} has an authorizer configured at api level"
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have an authorizer configured at api level."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_apigateway_one_rest_api_without_api_or_methods_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)

        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )

        default_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]

        api_resource = apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test"
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have authorizers at api level and the following paths and methods are unauthorized: /test -> GET."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_apigateway_one_rest_api_without_api_auth_but_one_method_auth(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)

        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )

        default_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]

        api_resource = apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test"
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="GET",
            authorizationType="AWS_IAM",
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} has all methods authorized"
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_apigateway_one_rest_api_without_api_auth_but_methods_auth_and_not(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)

        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )

        default_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]

        api_resource = apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test"
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="POST",
            authorizationType="AWS_IAM",
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have authorizers at api level and the following paths and methods are unauthorized: /test -> GET."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_apigateway_one_rest_api_without_api_auth_but_methods_not_auth_and_auth(
        self,
    ):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)

        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )

        default_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]

        api_resource = apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test"
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )

        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=api_resource["id"],
            httpMethod="POST",
            authorizationType="AWS_IAM",
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have authorizers at api level and the following paths and methods are unauthorized: /test -> GET."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_apigateway_one_rest_api_without_authorizers_with_various_resources_without_endpoints(
        self,
    ):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)

        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )

        default_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]

        apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test"
        )

        apigateway_client.create_resource(
            restApiId=rest_api["id"], parentId=default_resource_id, pathPart="test2"
        )

        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_restapi_authorizers_enabled.apigateway_restapi_authorizers_enabled.apigateway_client",
            new=APIGateway(aws_provider),
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
                == f"API Gateway test-rest-api ID {rest_api['id']} does not have an authorizer configured at api level."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]
