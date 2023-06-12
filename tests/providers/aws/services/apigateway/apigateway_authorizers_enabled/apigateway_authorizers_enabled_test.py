from unittest import mock

from boto3 import client, session
from moto import mock_apigateway, mock_iam, mock_lambda
from moto.core import DEFAULT_ACCOUNT_ID as ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_apigateway_authorizers_enabled:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
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
            "prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled import (
                apigateway_authorizers_enabled,
            )

            check = apigateway_authorizers_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_apigateway
    @mock_iam
    @mock_lambda
    def test_apigateway_one_rest_api_with_lambda_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        lambda_client = client("lambda", region_name=AWS_REGION)
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
            authorizerUri=f"arn:aws:apigateway:{apigateway_client.meta.region_name}:lambda:path/2015-03-31/functions/arn:aws:lambda:{apigateway_client.meta.region_name}:{ACCOUNT_ID}:function:{authorizer['FunctionName']}/invocations",
        )
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled import (
                apigateway_authorizers_enabled,
            )

            check = apigateway_authorizers_enabled()
            result = check.execute()

            assert result[0].status == "PASS"
            assert len(result) == 1
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} has authorizer configured."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/restapis/{rest_api['id']}"
            )

    @mock_apigateway
    def test_apigateway_one_rest_api_without_lambda_authorizer(self):
        # Create APIGateway Mocked Resources
        apigateway_client = client("apigateway", region_name=AWS_REGION)
        # Create APIGateway Rest API
        rest_api = apigateway_client.create_rest_api(
            name="test-rest-api",
        )
        from prowler.providers.aws.services.apigateway.apigateway_service import (
            APIGateway,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled.apigateway_client",
            new=APIGateway(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.apigateway.apigateway_authorizers_enabled.apigateway_authorizers_enabled import (
                apigateway_authorizers_enabled,
            )

            check = apigateway_authorizers_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert len(result) == 1
            assert (
                result[0].status_extended
                == f"API Gateway test-rest-api ID {rest_api['id']} has not authorizer configured."
            )
            assert result[0].resource_id == "test-rest-api"
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:apigateway:{AWS_REGION}::/restapis/{rest_api['id']}"
            )
