from boto3 import client, session
from moto import mock_apigateway

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.apigateway.apigateway_service import APIGateway

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_APIGateway_Service:
    # Mocked Audit Info
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
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test APIGateway Service
    @mock_apigateway
    def test_service(self):
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.service == "apigateway"

    # Test APIGateway Client
    @mock_apigateway
    def test_client(self):
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        for regional_client in apigateway.regional_clients.values():
            assert regional_client.__class__.__name__ == "APIGateway"

    # Test APIGateway Session
    @mock_apigateway
    def test__get_session__(self):
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.session.__class__.__name__ == "Session"

    # Test APIGateway Session
    @mock_apigateway
    def test_audited_account(self):
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.audited_account == AWS_ACCOUNT_NUMBER

    # Test APIGateway Get Rest APIs
    @mock_apigateway
    def test__get_rest_apis__(self):
        # Generate APIGateway Client
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Rest API
        apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert len(apigateway.rest_apis) == len(
            apigateway_client.get_rest_apis()["items"]
        )

    # Test APIGateway Get Authorizers
    @mock_apigateway
    def test__get_authorizers__(self):
        # Generate APIGateway Client
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Rest API
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        # Create authorizer
        apigateway_client.create_authorizer(
            name="test-authorizer",
            restApiId=rest_api["id"],
            type="TOKEN",
        )
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.rest_apis[0].authorizer is True

    # Test APIGateway Get Rest API
    @mock_apigateway
    def test__get_rest_api__(self):
        # Generate APIGateway Client
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create private APIGateway Rest API
        apigateway_client.create_rest_api(
            name="test-rest-api",
            endpointConfiguration={"types": ["PRIVATE"]},
            tags={"test": "test"},
        )
        # APIGateway client for this test class
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.rest_apis[0].public_endpoint is False
        assert apigateway.rest_apis[0].tags == [{"test": "test"}]

    # Test APIGateway Get Stages
    @mock_apigateway
    def test__get_stages__(self):
        # Generate APIGateway Client
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Rest API and a deployment stage
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
        apigateway_client.update_stage(
            restApiId=rest_api["id"],
            stageName="test",
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/*/*/logging/loglevel",
                    "value": "INFO",
                },
            ],
        )
        audit_info = self.set_mocked_audit_info()
        apigateway = APIGateway(audit_info)
        assert apigateway.rest_apis[0].stages[0].logging is True
