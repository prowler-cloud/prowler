from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.drs.drs_service import DRS

# Mock Test Region
AWS_REGION = "us-east-1"

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "DescribeJobs":
        return {
            "items": [
                {
                    "arn": "arn:aws:disaster-recovery:us-east-1:123456789012:job/jobID1",
                    "creationDateTime": datetime(2024, 1, 1),
                    "endDateTime": datetime(2024, 1, 1),
                    "initiatedBy": "START_RECOVERY",
                    "jobID": "jobID1",
                    "participatingServers": [
                        {
                            "launchStatus": "PENDING",
                            "recoveryInstanceID": "i-1234567890abcdef0",
                            "sourceServerID": "i-1234567890abcdef0",
                        },
                    ],
                    "status": "PENDING",
                    "tags": {"test_tag": "test_value"},
                    "type": "LAUNCH",
                },
            ]
        }

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.drs.drs_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_DRS_Service:

    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
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

    def test__get_client__(self):
        audit_info = self.set_mocked_audit_info()
        drs = DRS(audit_info)
        assert drs.regional_clients[AWS_REGION].__class__.__name__ == "drs"

    def test__get_service__(self):
        audit_info = self.set_mocked_audit_info()
        drs = DRS(audit_info)
        assert drs.service == "drs"

    def test__describe_jobs__(self):
        audit_info = self.set_mocked_audit_info()
        drs = DRS(audit_info)
        assert len(drs.drs_jobs) == 1
        assert (
            drs.drs_jobs[0].arn
            == "arn:aws:disaster-recovery:us-east-1:123456789012:job/jobID1"
        )
        assert drs.drs_jobs[0].id == "jobID1"
        assert drs.drs_jobs[0].region == AWS_REGION
        assert drs.drs_jobs[0].tags == [{"test_tag": "test_value"}]
        assert len(drs.drss) == 1
        assert drs.drss[0].id == "DRS"
        assert drs.drss[0].region == AWS_REGION
        assert drs.drss[0].status == "ENABLED"


        
