from unittest import mock

from boto3 import client
from moto import mock_apigateway

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

API_GW_NAME = "test-rest-api"


class Test_apigateway_restapi_public_with_authorizer:
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
            "prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer import (
                apigateway_restapi_public_with_authorizer,
            )

            check = apigateway_restapi_public_with_authorizer()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    def test_apigateway_one_public_rest_api_without_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        # Create APIGateway Deployment Stage
        rest_api = apigateway_client.create_rest_api(
            name=API_GW_NAME,
            endpointConfiguration={
                "types": [
                    "EDGE",
                ]
            },
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
            "prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer import (
                apigateway_restapi_public_with_authorizer,
            )

            check = apigateway_restapi_public_with_authorizer()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"API Gateway REST API {API_GW_NAME} with ID {rest_api['id']} has a public endpoint without an authorizer."
            )
            assert result[0].resource_id == API_GW_NAME
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_apigateway
    def test_apigateway_one_public_rest_api_with_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION_US_EAST_1)
        # Create APIGateway Deployment Stage
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
            endpointConfiguration={
                "types": [
                    "EDGE",
                ]
            },
        )
        apigateway_client.create_authorizer(
            restApiId=rest_api["id"], name="test-rest-api-with-authorizer", type="TOKEN"
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
            "prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_restapi_public_with_authorizer.apigateway_restapi_public_with_authorizer import (
                apigateway_restapi_public_with_authorizer,
            )

            check = apigateway_restapi_public_with_authorizer()
            result = check.execute()

            assert result[0].status == "PASS"
            assert len(result) == 1
            assert (
                result[0].status_extended
                == f"API Gateway REST API {API_GW_NAME} with ID {rest_api['id']} has a public endpoint with an authorizer."
            )
            assert result[0].resource_id == API_GW_NAME
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION_US_EAST_1}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]
