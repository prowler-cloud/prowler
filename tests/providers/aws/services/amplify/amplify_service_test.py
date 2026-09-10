from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.amplify.amplify_service import Amplify, App, Branch
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

app_id = "app-12345"
app_name = "test-app"
app_arn = f"arn:aws:amplify:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apps/{app_id}"
branch_name = "main"
branch_arn = f"{app_arn}/branches/{branch_name}"

app_environment_variables = {"app_key": "app_val"}
branch_environment_variables = {"branch_key": "branch_val"}
build_spec = "version: 1"
app_tags = {"tag_key": "tag_val"}

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListApps":
        return {
            "apps": [
                {
                    "appId": app_id,
                    "name": app_name,
                    "appArn": app_arn,
                    "environmentVariables": app_environment_variables,
                    "buildSpec": build_spec,
                    "tags": app_tags,
                }
            ]
        }
    if operation_name == "ListBranches":
        return {
            "branches": [
                {
                    "branchArn": branch_arn,
                    "branchName": branch_name,
                    "environmentVariables": branch_environment_variables,
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class TestAmplifyService:
    @mock_aws
    def test_amplify_service(self):
        amplify = Amplify(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert amplify.session.__class__.__name__ == "Session"
        assert amplify.service == "amplify"
        assert len(amplify.apps) == 1
        assert isinstance(amplify.apps[app_arn], App)

        app = amplify.apps[app_arn]
        assert app.id == app_id
        assert app.name == app_name
        assert app.arn == app_arn
        assert app.region == AWS_REGION_US_EAST_1
        assert app.environment_variables == app_environment_variables
        assert app.build_spec == build_spec
        assert app.tags == [app_tags]

        assert len(app.branches) == 1
        branch = app.branches[0]
        assert isinstance(branch, Branch)
        assert branch.name == branch_name
        assert branch.arn == branch_arn
        assert branch.environment_variables == branch_environment_variables
