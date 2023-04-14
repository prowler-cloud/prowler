import datetime
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.macie.macie_service import Macie, Session

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Mocking Macie2 Calls
make_api_call = botocore.client.BaseClient._make_api_call

# As you can see the operation_name has the list_sessions snake_case form but
# we are using the GetMacieSession form.
# Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
#
# We have to mock every AWS API call using Boto3


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetMacieSession":
        return {
            "createdAt": datetime(2015, 1, 1),
            "findingPublishingFrequency": "SIX_HOURS",
            "serviceRole": "string",
            "status": "ENABLED",
            "updatedAt": datetime(2015, 1, 1),
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.macie.macie_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Macie_Service:
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

    # Test Macie Client
    def test__get_client__(self):
        macie = Macie(self.set_mocked_audit_info())
        assert macie.regional_clients[AWS_REGION].__class__.__name__ == "Macie2"

    # Test Macie Session
    def test__get_session__(self):
        macie = Macie(self.set_mocked_audit_info())
        assert macie.session.__class__.__name__ == "Session"

    # Test Macie Service
    def test__get_service__(self):
        macie = Macie(self.set_mocked_audit_info())
        assert macie.service == "macie2"

    def test__get_macie_session__(self):
        # Set partition for the service
        macie = Macie(self.set_mocked_audit_info())
        macie.sessions = [
            Session(
                status="ENABLED",
                region="eu-west-1",
            )
        ]
        assert len(macie.sessions) == 1
        assert macie.sessions[0].status == "ENABLED"
        assert macie.sessions[0].region == AWS_REGION
