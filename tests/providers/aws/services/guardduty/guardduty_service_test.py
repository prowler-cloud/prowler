from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

AWS_ACCOUNT_NUMBER_ADMIN = "123456789013"


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
class Test_GuardDuty_Service:
    # Test GuardDuty Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)
        assert guardduty.service == "guardduty"

    # Test GuardDuty client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)
        for reg_client in guardduty.regional_clients.values():
            assert reg_client.__class__.__name__ == "GuardDuty"

    # Test GuardDuty session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)
        assert guardduty.session.__class__.__name__ == "Session"

    @mock_aws
    # Test GuardDuty session
    def test_list_detectors(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        response = guardduty_client.create_detector(Enable=True, Tags={"test": "test"})

        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert (
            guardduty.detectors[0].arn
            == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert guardduty.detectors[0].enabled_in_account
        assert len(guardduty.detectors[0].findings) == 1
        assert guardduty.detectors[0].member_accounts == ["123456789012"]
        assert guardduty.detectors[0].administrator_account == "123456789013"
        assert guardduty.detectors[0].region == AWS_REGION_EU_WEST_1
        assert guardduty.detectors[0].tags == [{"test": "test"}]

    @mock_aws
    # Test GuardDuty session
    def test_get_detector(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        response = guardduty_client.create_detector(
            Enable=True,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
            Features=[
                {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"},
                {"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"},
            ],
        )

        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert (
            guardduty.detectors[0].arn
            == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert guardduty.detectors[0].enabled_in_account
        assert len(guardduty.detectors[0].findings) == 1
        assert guardduty.detectors[0].member_accounts == ["123456789012"]
        assert guardduty.detectors[0].administrator_account == "123456789013"
        assert guardduty.detectors[0].s3_protection
        assert not guardduty.detectors[0].rds_protection
        assert guardduty.detectors[0].eks_audit_log_protection
        assert guardduty.detectors[0].eks_runtime_monitoring
        assert guardduty.detectors[0].lambda_protection
        assert not guardduty.detectors[0].ec2_malware_protection
        assert guardduty.detectors[0].region == AWS_REGION_EU_WEST_1
        assert guardduty.detectors[0].tags == [{"test": "test"}]

    @mock_aws
    # Test GuardDuty session
    def test_list_findings(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        response = guardduty_client.create_detector(Enable=True)

        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert (
            guardduty.detectors[0].arn
            == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert guardduty.detectors[0].enabled_in_account
        assert len(guardduty.detectors[0].findings) == 1
        assert guardduty.detectors[0].member_accounts == ["123456789012"]
        assert guardduty.detectors[0].administrator_account == "123456789013"
        assert guardduty.detectors[0].region == AWS_REGION_EU_WEST_1
        assert guardduty.detectors[0].tags == [{"test": "test"}]

    @mock_aws
    def test_list_members(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        response = guardduty_client.create_detector(Enable=True)

        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert (
            guardduty.detectors[0].arn
            == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert guardduty.detectors[0].enabled_in_account
        assert len(guardduty.detectors[0].findings) == 1
        assert guardduty.detectors[0].member_accounts == ["123456789012"]
        assert guardduty.detectors[0].administrator_account == "123456789013"
        assert guardduty.detectors[0].region == AWS_REGION_EU_WEST_1
        assert guardduty.detectors[0].tags == [{"test": "test"}]

    @mock_aws
    # Test GuardDuty session
    def test_get_administrator_account(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        response = guardduty_client.create_detector(Enable=True)

        aws_provider = set_mocked_aws_provider()
        guardduty = GuardDuty(aws_provider)

        assert len(guardduty.detectors) == 1
        assert guardduty.detectors[0].id == response["DetectorId"]
        assert (
            guardduty.detectors[0].arn
            == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{response['DetectorId']}"
        )
        assert guardduty.detectors[0].enabled_in_account
        assert len(guardduty.detectors[0].findings) == 1
        assert guardduty.detectors[0].member_accounts == ["123456789012"]
        assert guardduty.detectors[0].administrator_account == "123456789013"
        assert guardduty.detectors[0].region == AWS_REGION_EU_WEST_1
        assert guardduty.detectors[0].tags == [{"test": "test"}]
