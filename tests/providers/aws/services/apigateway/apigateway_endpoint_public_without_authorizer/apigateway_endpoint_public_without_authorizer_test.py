from unittest import mock

from boto3 import client, session
from moto import mock_apigateway

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"

API_GW_NAME = "test-rest-api"


class Test_apigateway_endpoint_public_without_authorizer:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_apigateway
    def test_apigateway_no_rest_apis(self):
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer import (
                apigateway_endpoint_public_without_authorizer,
            )

            check = apigateway_endpoint_public_without_authorizer()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    def test_apigateway_one_public_rest_api_without_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
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

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer import (
                apigateway_endpoint_public_without_authorizer,
            )

            check = apigateway_endpoint_public_without_authorizer()
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
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == [{}]

    @mock_apigateway
    def test_apigateway_one_public_rest_api_with_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
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

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_endpoint_public_without_authorizer.apigateway_endpoint_public_without_authorizer import (
                apigateway_endpoint_public_without_authorizer,
            )

            check = apigateway_endpoint_public_without_authorizer()
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
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/restapis/{rest_api['id']}"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == [{}]
