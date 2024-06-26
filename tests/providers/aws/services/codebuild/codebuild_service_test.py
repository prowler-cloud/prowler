from datetime import datetime, timedelta
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.codebuild.codebuild_service import (
    Build,
    Codebuild,
    Project,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

project_name = "test"
project_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
build_spec_project_arn = "arn:aws:s3:::my-codebuild-sample2/buildspec.yml"
buildspec_type = "S3"
build_id = "test:93f838a7-cd20-48ae-90e5-c10fbbc78ca6"
last_invoked_time = datetime.now() - timedelta(days=2)

# Mocking batch_get_projects
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListProjects":
        return {"projects": [project_name]}
    if operation_name == "ListBuildsForProject":
        return {"ids": [build_id]}
    if operation_name == "BatchGetBuilds":
        return {"builds": [{"endTime": last_invoked_time}]}
    if operation_name == "BatchGetProjects":
        return {
            "projects": [
                {
                    "source": {
                        "type": buildspec_type,
                        "buildspec": build_spec_project_arn,
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
    def test_codebuild_service(self):
        codebuild = Codebuild(set_mocked_aws_provider())

        assert codebuild.session.__class__.__name__ == "Session"
        assert codebuild.service == "codebuild"

        assert len(codebuild.projects) == 1
        assert isinstance(codebuild.projects, dict)
        assert isinstance(codebuild.projects[project_arn], Project)
        assert codebuild.projects[project_arn].name == project_name
        assert codebuild.projects[project_arn].arn == project_arn
        assert codebuild.projects[project_arn].region == AWS_REGION_EU_WEST_1
        assert codebuild.projects[project_arn].last_invoked_time == last_invoked_time
        assert codebuild.projects[project_arn].last_build == Build(id=build_id)
        assert codebuild.projects[project_arn].buildspec == build_spec_project_arn
