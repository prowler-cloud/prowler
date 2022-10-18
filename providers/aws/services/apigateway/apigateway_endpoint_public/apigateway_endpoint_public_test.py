from unittest import mock

from boto3 import client
from moto import mock_apigateway


class Test_apigateway_endpoint_public:
    @mock_apigateway
    def test_apigateway_no_rest_apis(self):
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.apigateway.apigateway_service import APIGateway

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public import (
                apigateway_endpoint_public,
            )

            check = apigateway_endpoint_public()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    def test_apigateway_one_private_rest_api(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway")
        # Create APIGateway Deployment Stage
        apigateway_client.create_rest_api(
            name="test-rest-api",
            endpointConfiguration={
                "types": [
                    "PRIVATE",
                ]
            },
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.apigateway.apigateway_service import APIGateway

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public import (
                apigateway_endpoint_public,
            )

            check = apigateway_endpoint_public()
            result = check.execute()

            assert result[0].status == "PASS"

    @mock_apigateway
    def test_apigateway_one_prublic_rest_api(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway")
        # Create APIGateway Deployment Stage
        apigateway_client.create_rest_api(
            name="test-rest-api",
            endpointConfiguration={
                "types": [
                    "EDGE",
                ]
            },
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.apigateway.apigateway_service import APIGateway

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public import (
                apigateway_endpoint_public,
            )

            check = apigateway_endpoint_public()
            result = check.execute()

            assert result[0].status == "FAIL"

    @mock_apigateway
    def test_bad_response(self):
        mock_client = mock.MagicMock()

        with mock.patch(
            "providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public.apigateway_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.apigateway.apigateway_endpoint_public.apigateway_endpoint_public import (
                apigateway_endpoint_public,
            )

            check = apigateway_endpoint_public()
            result = check.execute()

            assert len(result) == 0
