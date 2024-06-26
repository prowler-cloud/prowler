from datetime import datetime
from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    AuthenticationProtocol,
    CertificateState,
    CertificateType,
    DirectoryService,
    DirectoryType,
    EventTopicStatus,
    RadiusStatus,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "DescribeDirectories":
        return {
            "DirectoryDescriptions": [
                {
                    "DirectoryId": "d-12345a1b2",
                    "Name": "test-directory",
                    "Type": "MicrosoftAD",
                    "ShortName": "test-directory",
                    "RadiusSettings": {
                        "RadiusServers": [
                            "test-server",
                        ],
                        "RadiusPort": 9999,
                        "RadiusTimeout": 100,
                        "RadiusRetries": 100,
                        "SharedSecret": "test-shared-secret",
                        "AuthenticationProtocol": "MS-CHAPv2",
                        "DisplayLabel": "test-directory",
                        "UseSameUsername": True | False,
                    },
                    "RadiusStatus": "Creating",
                },
            ],
        }
    if operation_name == "ListLogSubscriptions":
        return {
            "LogSubscriptions": [
                {
                    "DirectoryId": "d-12345a1b2",
                    "LogGroupName": "test-log-group",
                    "SubscriptionCreatedDateTime": datetime(2022, 1, 1),
                },
            ],
        }
    if operation_name == "DescribeEventTopics":
        return {
            "EventTopics": [
                {
                    "DirectoryId": "d-12345a1b2",
                    "TopicName": "test-topic",
                    "TopicArn": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:test-topic",
                    "CreatedDateTime": datetime(2022, 1, 1),
                    "Status": "Registered",
                },
            ]
        }

    if operation_name == "ListCertificates":
        return {
            "CertificatesInfo": [
                {
                    "CertificateId": "test-certificate",
                    "CommonName": "test-certificate",
                    "State": "Registered",
                    "ExpiryDateTime": datetime(2023, 1, 1),
                    "Type": "ClientLDAPS",
                },
            ]
        }
    if operation_name == "GetSnapshotLimits":
        return {
            "SnapshotLimits": {
                "ManualSnapshotsLimit": 123,
                "ManualSnapshotsCurrentCount": 123,
                "ManualSnapshotsLimitReached": True,
            }
        }
    if operation_name == "ListTagsForResource":
        return {
            "Tags": [
                {"Key": "string", "Value": "string"},
            ],
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_DirectoryService_Service:
    # Test DirectoryService Client
    @mock_aws
    def test__get_client__(self):
        directoryservice = DirectoryService(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert (
            directoryservice.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "DirectoryService"
        )

    # Test DirectoryService Session
    @mock_aws
    def test__get_session__(self):
        directoryservice = DirectoryService(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert directoryservice.session.__class__.__name__ == "Session"

    # Test DirectoryService Service
    @mock_aws
    def test__get_service__(self):
        directoryservice = DirectoryService(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert directoryservice.service == "ds"

    @mock_aws
    def test__describe_directories__(self):
        # Set partition for the service
        directoryservice = DirectoryService(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )

        # __describe_directories__
        assert directoryservice.directories["d-12345a1b2"].id == "d-12345a1b2"
        assert (
            directoryservice.directories["d-12345a1b2"].arn
            == f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        assert (
            directoryservice.directories["d-12345a1b2"].type
            == DirectoryType.MicrosoftAD
        )
        assert directoryservice.directories["d-12345a1b2"].name == "test-directory"
        assert (
            directoryservice.directories["d-12345a1b2"].region == AWS_REGION_EU_WEST_1
        )
        assert directoryservice.directories["d-12345a1b2"].tags == [
            {"Key": "string", "Value": "string"},
        ]
        assert (
            directoryservice.directories[
                "d-12345a1b2"
            ].radius_settings.authentication_protocol
            == AuthenticationProtocol.MS_CHAPv2
        )
        assert (
            directoryservice.directories["d-12345a1b2"].radius_settings.status
            == RadiusStatus.Creating
        )

        # __list_log_subscriptions__
        assert len(directoryservice.directories["d-12345a1b2"].log_subscriptions) == 1
        assert (
            directoryservice.directories["d-12345a1b2"]
            .log_subscriptions[0]
            .log_group_name
            == "test-log-group"
        )
        assert directoryservice.directories["d-12345a1b2"].log_subscriptions[
            0
        ].created_date_time == datetime(2022, 1, 1)

        # __describe_event_topics__
        assert len(directoryservice.directories["d-12345a1b2"].event_topics) == 1
        assert (
            directoryservice.directories["d-12345a1b2"].event_topics[0].topic_name
            == "test-topic"
        )
        assert (
            directoryservice.directories["d-12345a1b2"].event_topics[0].topic_arn
            == f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:test-topic"
        )
        assert (
            directoryservice.directories["d-12345a1b2"].event_topics[0].status
            == EventTopicStatus.Registered
        )
        assert directoryservice.directories["d-12345a1b2"].event_topics[
            0
        ].created_date_time == datetime(2022, 1, 1)

        # __list_certificates__
        assert len(directoryservice.directories["d-12345a1b2"].certificates) == 1
        assert (
            directoryservice.directories["d-12345a1b2"].certificates[0].id
            == "test-certificate"
        )
        assert (
            directoryservice.directories["d-12345a1b2"].certificates[0].common_name
            == "test-certificate"
        )
        assert (
            directoryservice.directories["d-12345a1b2"].certificates[0].state
            == CertificateState.Registered
        )
        assert directoryservice.directories["d-12345a1b2"].certificates[
            0
        ].expiry_date_time == datetime(2023, 1, 1)
        assert (
            directoryservice.directories["d-12345a1b2"].certificates[0].type
            == CertificateType.ClientLDAPS
        )

        # __get_snapshot_limits__
        assert directoryservice.directories["d-12345a1b2"].snapshots_limits
        assert (
            directoryservice.directories[
                "d-12345a1b2"
            ].snapshots_limits.manual_snapshots_limit
            == 123
        )
        assert (
            directoryservice.directories[
                "d-12345a1b2"
            ].snapshots_limits.manual_snapshots_current_count
            == 123
        )
        assert (
            directoryservice.directories[
                "d-12345a1b2"
            ].snapshots_limits.manual_snapshots_limit_reached
            is True
        )
