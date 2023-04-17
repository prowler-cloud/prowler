from datetime import datetime, timedelta
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

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
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.codebuild.codebuild_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Codebuild_Service:
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
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test Codebuild Session
    def test__get_session__(self):
        codebuild = Codebuild(self.set_mocked_audit_info())
        assert codebuild.session.__class__.__name__ == "Session"

    # Test Codebuild Service
    def test__get_service__(self):
        codebuild = Codebuild(self.set_mocked_audit_info())
        assert codebuild.service == "codebuild"

    def test__list_projects__(self):
        codebuild = Codebuild(self.set_mocked_audit_info())
        assert len(codebuild.projects) == 1
        assert codebuild.projects[0].name == "test"
        assert codebuild.projects[0].region == AWS_REGION

    def test__list_builds_for_project__(self):
        codebuild = Codebuild(self.set_mocked_audit_info())
        assert len(codebuild.projects) == 1
        assert codebuild.projects[0].name == "test"
        assert codebuild.projects[0].region == AWS_REGION
        assert codebuild.projects[0].last_invoked_time == last_invoked_time
        assert (
            codebuild.projects[0].buildspec
            == "arn:aws:s3:::my-codebuild-sample2/buildspec.yml"
        )
