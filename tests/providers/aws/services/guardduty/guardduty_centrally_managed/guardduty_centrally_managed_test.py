from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_guardduty

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_NUMBER_ADMIN = "123456789013"


# Mocking Backup Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_central_managed(self, operation_name, kwarg):
    """
    Mock unsoportted AWS API call
    """
    if operation_name == "ListMembers":
        return {
            "Members": [],
        }
    if operation_name == "GetAdministratorAccount":
        return {
            "Administrator": {
                "AccountId": AWS_ACCOUNT_NUMBER_ADMIN,
                "InvitationId": "string",
                "RelationshipStatus": "string",
                "InvitedAt": "string",
            }
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_administrator(self, operation_name, kwarg):
    """
    Mock unsoportted AWS API call
    """
    if operation_name == "ListMembers":
        return {
            "Members": [
                {
                    "AccountId": "string",
                    "DetectorId": "string",
                    "MasterId": "string",
                    "Email": "string",
                    "RelationshipStatus": "string",
                    "InvitedAt": "string",
                    "UpdatedAt": "string",
                    "AdministratorId": "string",
                },
            ],
        }
    if operation_name == "GetAdministratorAccount":
        return {}
    return make_api_call(self, operation_name, kwarg)


class Test_guardduty_centrally_managed:
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
            profile_region="us-east-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_guardduty
    def test_no_detectors(self):
        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
                new=GuardDuty(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                    guardduty_centrally_managed,
                )

                check = guardduty_centrally_managed()
                result = check.execute()
                assert len(result) == 0

    @mock_guardduty
    def test_detector_no_centralized_managed(self):
        current_audit_info = self.set_mocked_audit_info()

        guardduty_client = client("guardduty", region_name="us-east-1")
        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
                new=GuardDuty(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                    guardduty_centrally_managed,
                )

                check = guardduty_centrally_managed()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"GuardDuty detector {detector_id} is not centrally managed"
                )
                assert result[0].resource_id == detector_id
                assert result[0].region == "us-east-1"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:guardduty:us-east-1:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                )

    @mock_guardduty
    # Patch with mock_make_api_call_central_managed:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_central_managed,
    )
    def test_detector_centralized_managed(self):
        current_audit_info = self.set_mocked_audit_info()

        guardduty_client = client("guardduty", region_name="us-east-1")
        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
                new=GuardDuty(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                    guardduty_centrally_managed,
                )

                check = guardduty_centrally_managed()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"GuardDuty detector {detector_id} is centrally managed by account {AWS_ACCOUNT_NUMBER_ADMIN}"
                )
                assert result[0].resource_id == detector_id
                assert result[0].region == "us-east-1"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:guardduty:us-east-1:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                )

    @mock_guardduty
    # Patch with mock_make_api_call_administrator:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_administrator,
    )
    def test_detector_administrator(self):
        current_audit_info = self.set_mocked_audit_info()

        guardduty_client = client("guardduty", region_name="us-east-1")
        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
                new=GuardDuty(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                    guardduty_centrally_managed,
                )

                check = guardduty_centrally_managed()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"GuardDuty detector {detector_id} is administrator account with 1 member accounts"
                )
                assert result[0].resource_id == detector_id
                assert result[0].region == "us-east-1"
                assert (
                    result[0].resource_arn
                    == f"arn:aws:guardduty:us-east-1:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                )
