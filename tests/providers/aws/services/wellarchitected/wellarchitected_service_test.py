from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"


workload_id = str(uuid4())

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListWorkloads":
        return {
            "WorkloadSummaries": [
                {
                    "WorkloadId": workload_id,
                    "WorkloadArn": f"arn:aws:wellarchitected:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:workload/{workload_id}",
                    "WorkloadName": "test",
                    "Owner": AWS_ACCOUNT_NUMBER,
                    "UpdatedAt": "2023-06-07T15:40:24+02:00",
                    "Lenses": ["wellarchitected", "serverless", "softwareasaservice"],
                    "RiskCounts": {"UNANSWERED": 56, "NOT_APPLICABLE": 4, "HIGH": 10},
                    "ImprovementStatus": "NOT_APPLICABLE",
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {
            "Tags": {"Key": "test", "Value": "test"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WellArchitected_Service:
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test WellArchitected Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(audit_info)
        assert wellarchitected.service == "wellarchitected"

    # Test WellArchitected client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(audit_info)
        for reg_client in wellarchitected.regional_clients.values():
            assert reg_client.__class__.__name__ == "WellArchitected"

    # Test WellArchitected session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(audit_info)
        assert wellarchitected.session.__class__.__name__ == "Session"

    # Test WellArchitected list workloads
    def test__list_workloads__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(audit_info)
        assert len(wellarchitected.workloads) == 1
        assert wellarchitected.workloads[0].id == workload_id
        assert (
            wellarchitected.workloads[0].arn
            == f"arn:aws:wellarchitected:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:workload/{workload_id}"
        )
        assert wellarchitected.workloads[0].name == "test"
        assert wellarchitected.workloads[0].region == AWS_REGION
        assert wellarchitected.workloads[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert wellarchitected.workloads[0].lenses == [
            "wellarchitected",
            "serverless",
            "softwareasaservice",
        ]
        assert wellarchitected.workloads[0].improvement_status == "NOT_APPLICABLE"
        assert wellarchitected.workloads[0].risks == {
            "UNANSWERED": 56,
            "NOT_APPLICABLE": 4,
            "HIGH": 10,
        }
