from datetime import datetime, timedelta
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.codebuild.codebuild_service import (
    Build,
    Codebuild,
    Project,
    s3Logs,
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
source_type = "BITBUCKET"
build_id = "test:93f838a7-cd20-48ae-90e5-c10fbbc78ca6"
last_invoked_time = datetime.now() - timedelta(days=2)
bitbucket_url = "https://bitbucket.org/example/repo.git"
secondary_bitbucket_url = "https://bitbucket.org/example/secondary-repo.git"

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
                        "type": source_type,
                        "location": bitbucket_url,
                        "buildspec": build_spec_project_arn,
                    },
                    "secondarySources": [
                        {
                            "type": source_type,
                            "location": secondary_bitbucket_url,
                            "buildspec": "",
                        }
                    ],
                    "logsConfig": {
                        "s3Logs": {
                            "status": "ENABLED",
                            "location": "test-bucket",
                            "encryptionDisabled": False,
                        }
                    },
                    "tags": [{"key": "Name", "value": project_name}],
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


class Test_Codebuild_Service:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
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
        assert bitbucket_url == codebuild.projects[project_arn].source.location
        assert (
            secondary_bitbucket_url
            in codebuild.projects[project_arn].secondary_sources[0].location
        )
        assert isinstance(codebuild.projects[project_arn].s3_logs, s3Logs)
        assert codebuild.projects[project_arn].s3_logs.status == "ENABLED"
        assert codebuild.projects[project_arn].s3_logs.bucket_location == "test-bucket"
        assert codebuild.projects[project_arn].s3_logs.encrypted
        assert codebuild.projects[project_arn].tags[0]["key"] == "Name"
        assert codebuild.projects[project_arn].tags[0]["value"] == project_name
