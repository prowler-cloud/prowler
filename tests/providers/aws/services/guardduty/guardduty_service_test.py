from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_guardduty

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

AWS_ACCOUNT_NUMBER_ADMIN = "123456789013"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListFindings":
        return {"FindingIds": ["86c1d16c9ec63f634ccd087ae0d427ba1"]}
    if operation_name == "ListTagsForResource":
        return {"Tags": {"test": "test"}}
    if operation_name == "ListMembers":
        return {
            "Members": [
                {
                    "AccountId": AWS_ACCOUNT_NUMBER,
                    "DetectorId": "11b4a9318fd146914420a637a4a9248b",
                    "MasterId": AWS_ACCOUNT_NUMBER_ADMIN,
                    "Email": "security@prowler.com",
                    "RelationshipStatus": "Enabled",
                    "InvitedAt": datetime(2020, 1, 1),
                    "UpdatedAt": datetime(2021, 1, 1),
                    "AdministratorId": AWS_ACCOUNT_NUMBER_ADMIN,
                },
            ],
        }
    if operation_name == "GetAdministratorAccount":
        return {
            "Administrator": {
                "AccountId": AWS_ACCOUNT_NUMBER_ADMIN,
                "InvitationId": "12b1a931a981d1e1f1f452cf2fb3d515",
                "RelationshipStatus": "Enabled",
                "InvitedAt": datetime(2020, 1, 1),
            }
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.guardduty.guardduty_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_GuardDuty_Service:
    # Mocked Audit Info
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

    # Test GuardDuty Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)
        assert guardduty.service == "guardduty"

    # Test GuardDuty client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)
        for reg_client in guardduty.regional_clients.values():
            assert reg_client.__class__.__name__ == "GuardDuty"

    # Test GuardDuty session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)
        assert guardduty.session.__class__.__name__ == "Session"

    @mock_guardduty
    # Test GuardDuty session
    def test__list_detectors__(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION)
        response = guardduty_client.create_detector(Enable=True, Tags={"test": "test"})

        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert guardduty.detectors[0].region == AWS_REGION
        assert guardduty.detectors[0].tags == [{"test": "test"}]

    @mock_guardduty
    # Test GuardDuty session
    def test__get_detector__(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION)
        response = guardduty_client.create_detector(Enable=True)

        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert guardduty.detectors[0].region == AWS_REGION
        assert guardduty.detectors[0].status

    @mock_guardduty
    # Test GuardDuty session
    def test__list_findings__(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION)
        response = guardduty_client.create_detector(Enable=True)

        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert guardduty.detectors[0].region == AWS_REGION
        assert guardduty.detectors[0].status
        assert len(guardduty.detectors[0].findings) == 1

    @mock_guardduty
    def test__list_members__(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION)
        response = guardduty_client.create_detector(Enable=True)

        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert guardduty.detectors[0].region == AWS_REGION
        assert guardduty.detectors[0].status
        assert len(guardduty.detectors[0].member_accounts) == 1

    @mock_guardduty
    # Test GuardDuty session
    def test__get_administrator_account__(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION)
        response = guardduty_client.create_detector(Enable=True)

        audit_info = self.set_mocked_audit_info()
        guardduty = GuardDuty(audit_info)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert guardduty.detectors[0].region == AWS_REGION
        assert guardduty.detectors[0].status
        assert guardduty.detectors[0].administrator_account == AWS_ACCOUNT_NUMBER_ADMIN
