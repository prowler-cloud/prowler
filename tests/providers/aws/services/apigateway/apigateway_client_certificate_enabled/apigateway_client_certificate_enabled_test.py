from unittest import mock

from boto3 import client
from moto import mock_apigateway

from prowler.providers.aws.services.apigateway.apigateway_service import Stage

AWS_REGION = "us-east-1"


class Test_apigateway_client_certificate_enabled:
    @mock_apigateway
    def test_apigateway_no_stages(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Rest API
        apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    def test_apigateway_one_stage_without_certificate(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Deployment Stage
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        # Get the rest api's root id
        root_resource_id = apigateway_client.get_resources(restApiId=rest_api["id"])[
            "items"
        ][0]["id"]
        resource = apigateway_client.create_resource(
            restApiId=rest_api["id"],
            parentId=root_resource_id,
            pathPart="test-path",
        )
        apigateway_client.put_method(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )
        apigateway_client.put_integration(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            type="HTTP",
            integrationHttpMethod="POST",
            uri="http://test.com",
        )
        apigateway_client.create_deployment(
            restApiId=rest_api["id"],
            stageName="test",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} in stage test has not client certificate enabled."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/apis/{rest_api['id']}/stages/test"
            )

    @mock_apigateway
    def test_apigateway_one_stage_with_certificate(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Deployment Stage
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            service_client.rest_apis[0].stages.append(
                Stage(
                    name="test",
                    arn=f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/apis/test-rest-api/stages/test",
                    logging=True,
                    client_certificate=True,
                    waf=True,
                )
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} in stage test has client certificate enabled."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/apis/test-rest-api/stages/test"
            )
