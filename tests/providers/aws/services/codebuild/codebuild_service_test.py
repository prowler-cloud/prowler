from datetime import datetime, timedelta
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

# last time invoked time
last_invoked_time = datetime.now() - timedelta(days=2)


# Mocking batch_get_projects
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListProjects":
        return {"projects": ["test"]}
    if operation_name == "ListBuildsForProject":
        return {"ids": ["test:93f838a7-cd20-48ae-90e5-c10fbbc78ca6"]}
    if operation_name == "BatchGetBuilds":
        return {"builds": [{"endTime": last_invoked_time}]}
    if operation_name == "BatchGetProjects":
        return {
            "projects": [
                {
                    "source": {
                        "buildspec": "arn:aws:s3:::my-codebuild-sample2/buildspec.yml"
                    }
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Codebuild_Service:
    # Test Codebuild Session
    def test__get_session__(self):
        codebuild = Codebuild(set_mocked_aws_provider())
        assert codebuild.session.__class__.__name__ == "Session"

    # Test Codebuild Service
    def test__get_service__(self):
        codebuild = Codebuild(set_mocked_aws_provider())
        assert codebuild.service == "codebuild"

    def test__list_projects__(self):
        codebuild = Codebuild(set_mocked_aws_provider())
        assert len(codebuild.projects) == 1
        assert codebuild.projects[0].name == "test"
        assert codebuild.projects[0].region == AWS_REGION_EU_WEST_1

    def test__list_builds_for_project__(self):
        codebuild = Codebuild(set_mocked_aws_provider())
        assert len(codebuild.projects) == 1
        assert codebuild.projects[0].name == "test"
        assert codebuild.projects[0].region == AWS_REGION_EU_WEST_1
        assert codebuild.projects[0].last_invoked_time == last_invoked_time
        assert (
            codebuild.projects[0].buildspec
            == "arn:aws:s3:::my-codebuild-sample2/buildspec.yml"
        )
