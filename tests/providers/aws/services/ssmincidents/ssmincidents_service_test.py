from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    SSMIncidents,
)

# Mock Test Region
AWS_REGION = "us-east-1"
REPLICATION_SET_ARN = "arn:aws:ssm-incidents::111122223333:replication-set/40bd98f0-4110-2dee-b35e-b87006f9e172"
RESPONSE_PLAN_ARN = "arn:aws:ssm-incidents::111122223333:response-plan/example-response"

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListReplicationSets":
        return {"replicationSetArns": [REPLICATION_SET_ARN]}
    if operation_name == "GetReplicationSet":
        return {
            "replicationSet": {
                "arn": REPLICATION_SET_ARN,
                "createdBy": "thegaby",
                "createdTime": datetime(2024, 1, 1),
                "deletionProtected": False,
                "lastModifiedBy": datetime(2024, 1, 1),
                "lastModifiedTime": datetime(2024, 1, 1),
                "regionMap": {
                    AWS_REGION: {
                        "sseKmsKeyId": "DefaultKey",
                        "status": "ACTIVE",
                        "statusMessage": "Test",
                        "statusUpdateDateTime": datetime(2024, 1, 1),
                    }
                },
                "status": "ACTIVE",
            }
        }
    if operation_name == "ListResponsePlans":
        return {
            "responsePlanSummaries": [
                {"Arn": RESPONSE_PLAN_ARN, "displayName": "test", "Name": "test"}
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"tags": {"tag_test": "tag_value"}}

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.ssmincidents.ssmincidents_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SSMIncidents_Service:

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
        ssmincidents = SSMIncidents(audit_info)
        assert (
            ssmincidents.regional_clients[AWS_REGION].__class__.__name__
            == "SSMIncidents"
        )

    def test__get_service__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = SSMIncidents(audit_info)
        assert ssmincidents.service == "ssm-incidents"

    def test__list_replication_sets__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = SSMIncidents(audit_info)
        assert len(ssmincidents.replication_sets) == 1

    def test__get_replication_set__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = SSMIncidents(audit_info)
        assert ssmincidents.replication_sets[0].arn == REPLICATION_SET_ARN
        assert ssmincidents.replication_sets[0].status == "ACTIVE"
        for region in ssmincidents.replication_sets[0].region_map:
            assert region.region == AWS_REGION
            assert region.status == "ACTIVE"
            assert region.sse_kms_id == "DefaultKey"

    def test__list_response_plans__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = SSMIncidents(audit_info)
        assert len(ssmincidents.response_plans) == 1
        assert ssmincidents.response_plans[0].arn == RESPONSE_PLAN_ARN
        assert ssmincidents.response_plans[0].name == "test"
        assert ssmincidents.response_plans[0].region == AWS_REGION
        assert ssmincidents.response_plans[0].tags == {"tag_test": "tag_value"}

    def test__list_tags_for_resource__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = SSMIncidents(audit_info)
        assert len(ssmincidents.response_plans) == 1
        assert ssmincidents.response_plans[0].tags == {"tag_test": "tag_value"}
