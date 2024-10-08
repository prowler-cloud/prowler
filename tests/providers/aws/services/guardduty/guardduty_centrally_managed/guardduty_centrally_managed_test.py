from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call_admin_enabled(self, operation_name, api_params):
    if operation_name == "GetAdministratorAccount":
        return {
            "Administrator": {
                "AccountId": "210987654321",
            }
        }
    return orig(self, operation_name, api_params)


def mock_make_api_call_members_managers(self, operation_name, api_params):
    if operation_name == "ListMembers":
        return {
            "Members": [
                {
                    "AccountId": "210987654321",
                    "RelationshipStatus": "Enabled",
                }
            ]
        }
    return orig(self, operation_name, api_params)


class Test_guardduty_centrally_managed:
    @mock_aws
    def test_no_detectors(self):
        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                guardduty_centrally_managed,
            )

            check = guardduty_centrally_managed()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_detector_no_centralized_managed(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
            new=GuardDuty(aws_provider),
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
                == f"GuardDuty detector {detector_id} is not centrally managed."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
            assert result[0].resource_tags == []

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_admin_enabled,
    )
    @mock_aws
    def test_detector_centralized_managed(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
            new=GuardDuty(aws_provider),
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
                == f"GuardDuty detector {detector_id} is centrally managed by account 210987654321."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_members_managers,
    )
    @mock_aws
    def test_detector_members_accounts(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed.guardduty_client",
            new=GuardDuty(aws_provider),
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
                == f"GuardDuty detector {detector_id} is administrator account with 1 member accounts."
            )
            assert result[0].resource_id == detector_id
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
            )
