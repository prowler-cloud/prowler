from unittest import mock

from boto3 import client
from moto import mock_apigateway


class Test_apigateway_client_certificate_enabled:
    @mock_apigateway
    def test_apigateway_no_stages(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway")
        # Create APIGateway Rest API
        apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.apigateway.apigateway_service import APIGateway

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    def test_apigateway_one_stage_without_certificate(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway")
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
        deployment = apigateway_client.create_deployment(
            restApiId=rest_api["id"],
            stageName="test",
        )
        apigateway_client.create_stage(
            restApiId=rest_api["id"],
            stageName="test-stage",
            deploymentId=deployment["id"],
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.apigateway.apigateway_service import APIGateway

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"

    # @mock_apigateway
    # def test_apigateway_one_stage_with_certificate(self):
    # Pending to add test since it is not possible to attach a certificate to a stage

    # domain_name = "testDomain"
    # test_certificate_name = "test.certificate"
    # # Create APIGateway Mocked Resources
    # apigateway_client = client("apigateway")
    # # Create APIGateway Deployment Stage
    # rest_api = apigateway_client.create_rest_api(
    #     name="test-rest-api",
    # )
    # from providers.aws.lib.audit_info.audit_info import current_audit_info
    # from providers.aws.services.apigateway.apigateway_service import APIGateway
    # current_audit_info.audited_partition = "aws"

    # with mock.patch(
    #     "providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
    #     new=APIGateway(current_audit_info),
    # ):
    #     # Test Check
    #     from providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
    #         apigateway_client_certificate_enabled,
    #     )

    #     check = apigateway_client_certificate_enabled()
    #     result = check.execute()

    #     assert result[0].status == 'PASS'

    @mock_apigateway
    def test_bad_response(self):
        mock_client = mock.MagicMock()

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled.apigateway_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_client_certificate_enabled.apigateway_client_certificate_enabled import (
                apigateway_client_certificate_enabled,
            )

            check = apigateway_client_certificate_enabled()
            result = check.execute()

            assert len(result) == 0
