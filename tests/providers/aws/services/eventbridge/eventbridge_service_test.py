from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.eventbridge.eventbridge_service import (
    EventBridge,
    Schema,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListRegistries":
        return {
            "Registries": [
                {
                    "RegistryArn": "arn:aws:schemas:us-east-1:123456789012:registry/test",
                    "RegistryName": "test",
                    "Tags": {"key1": "value1"},
                },
            ]
        }
    if operation_name == "GetResourcePolicy":
        return {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Sid":"AllowReadWrite","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"schemas:*","Resource":"arn:aws:schemas:eu-west-1:123456789012:registry/test"}]}',
            "RevisionId": "1",
        }
    if operation_name == "ListEndpoints":
        return {
            "Endpoints": [
                {
                    "Name": "test-endpoint",
                    "Arn": f"arn:aws:events:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint",
                    "ReplicationConfig": {"State": "DISABLED"},
                }
            ]
        }

    return make_api_call(self, operation_name, kwargs)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_EventBridge_Service:
    # Test EventBridge Service
    @mock_aws
    def test_service(self):
        # EventBridge client for this test class
        aws_provider = set_mocked_aws_provider()
        eventbridge = EventBridge(aws_provider)
        assert eventbridge.service == "events"

    # Test EventBridge Client
    @mock_aws
    def test_client(self):
        # EventBridge client for this test class
        aws_provider = set_mocked_aws_provider()
        eventbridge = EventBridge(aws_provider)
        for client_ in eventbridge.regional_clients.values():
            assert client_.__class__.__name__ == "EventBridge"

    # Test EventBridge Session
    @mock_aws
    def test__get_session__(self):
        # EventBridge client for this test class
        aws_provider = set_mocked_aws_provider()
        eventbridge = EventBridge(aws_provider)
        assert eventbridge.session.__class__.__name__ == "Session"

    # Test EventBridge Session
    @mock_aws
    def test_audited_account(self):
        # EventBridge client for this test class
        aws_provider = set_mocked_aws_provider()
        eventbridge = EventBridge(aws_provider)
        assert eventbridge.audited_account == AWS_ACCOUNT_NUMBER

    # Test Schema Service
    @mock_aws
    def test_schema_service(self):
        # Schema client for this test class
        aws_provider = set_mocked_aws_provider()
        schema = Schema(aws_provider)
        assert schema.service == "schemas"

    # Test Schema Client
    @mock_aws
    def test_schema_client(self):
        # Schema client for this test class
        aws_provider = set_mocked_aws_provider()
        schema = Schema(aws_provider)
        for client_ in schema.regional_clients.values():
            assert client_.__class__.__name__ == "Schemas"

    # Test Schema Session
    @mock_aws
    def test__schema_get_session__(self):
        # Schema client for this test class
        aws_provider = set_mocked_aws_provider()
        schema = Schema(aws_provider)
        assert schema.session.__class__.__name__ == "Session"

    # Test Schema Session
    @mock_aws
    def test_schema_audited_account(self):
        # Schema client for this test class
        aws_provider = set_mocked_aws_provider()
        schema = Schema(aws_provider)
        assert schema.audited_account == AWS_ACCOUNT_NUMBER

    # Test EventBridge Buses
    @mock_aws
    def test_list_event_buses(self):
        # EventBridge client for this test class
        events_client = client("events", region_name=AWS_REGION_US_EAST_1)
        events_client.create_event_bus(Name="test")
        events_client.tag_resource(
            ResourceARN=f"arn:aws:events:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/test",
            Tags=[{"Key": "key-1", "Value": "value-1"}],
        )
        events_client.put_permission(
            EventBusName="test",
            Action="events:PutEvents",
            Principal="123456789012",
            StatementId="test-statement",
        )
        aws_provider = set_mocked_aws_provider()
        eventbridge = EventBridge(aws_provider)
        # Each region has a default bus, plus the "test" bus we created in us-east-1
        assert len(eventbridge.buses) == len(eventbridge.regional_clients) + 1
        for bus in eventbridge.buses.values():
            if bus.name == "test":
                assert (
                    bus.arn
                    == f"arn:aws:events:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/test"
                )
                assert bus.name == "test"
                assert bus.region == AWS_REGION_US_EAST_1
                assert bus.policy == {
                    "Statement": [
                        {
                            "Action": "events:PutEvents",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Resource": "arn:aws:events:us-east-1:123456789012:event-bus/test",
                            "Sid": "test-statement",
                        }
                    ],
                    "Version": "2012-10-17",
                }
                assert bus.tags == [{"Key": "key-1", "Value": "value-1"}]

    # Test Schema Registries
    def test_list_policies(self):
        aws_provider = set_mocked_aws_provider()
        schema = Schema(aws_provider)
        assert len(schema.registries) == 1
        schema_arn = "arn:aws:schemas:us-east-1:123456789012:registry/test"
        assert schema.registries[schema_arn].arn == schema_arn
        assert schema.registries[schema_arn].name == "test"
        assert schema.registries[schema_arn].tags == [{"key1": "value1"}]
        assert schema.registries[schema_arn].policy == {
            "Statement": [
                {
                    "Action": "schemas:*",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Resource": "arn:aws:schemas:eu-west-1:123456789012:registry/test",
                    "Sid": "AllowReadWrite",
                }
            ],
            "Version": "2012-10-17",
        }

    # Test EventBridge Endpoints
    def test_list_endpoints(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        eventbridge = EventBridge(aws_provider)
        assert len(eventbridge.endpoints) == 1
        endpoint_arn = f"arn:aws:events:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint"
        assert eventbridge.endpoints[endpoint_arn].name == "test-endpoint"
        assert (
            eventbridge.endpoints[endpoint_arn].arn
            == f"arn:aws:events:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint"
        )
        assert eventbridge.endpoints[endpoint_arn].replication_state == "DISABLED"
        assert eventbridge.endpoints[endpoint_arn].tags == []
        assert eventbridge.endpoints[endpoint_arn].region == AWS_REGION_US_EAST_1

    # Test EventBridge List Event Buses follows pagination
    @mock_aws
    def test_list_event_buses_follows_next_token_pagination(self):
        def bus(name):
            return {
                "Name": name,
                "Arn": (
                    f"arn:aws:events:{AWS_REGION_US_EAST_1}:"
                    f"{AWS_ACCOUNT_NUMBER}:event-bus/{name}"
                ),
            }

        pages = {
            "ListEventBuses": (
                {"EventBuses": [bus("test-bus-1")], "NextToken": "next"},
                {"EventBuses": [bus("test-bus-2")]},
            ),
        }

        def mock_paginated_api_call(self, operation_name, kwargs):
            if operation_name in pages:
                page_index = 1 if kwargs.get("NextToken") else 0
                return pages[operation_name][page_index]
            return mock_make_api_call(self, operation_name, kwargs)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_paginated_api_call,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            eventbridge = EventBridge(aws_provider)

        assert len(eventbridge.buses) == 2
        assert sorted(b.name for b in eventbridge.buses.values()) == [
            "test-bus-1",
            "test-bus-2",
        ]

    # Test EventBridge List Endpoints follows pagination
    @mock_aws
    def test_list_endpoints_follows_next_token_pagination(self):
        def endpoint(name):
            return {
                "Name": name,
                "Arn": (
                    f"arn:aws:events:{AWS_REGION_US_EAST_1}:"
                    f"{AWS_ACCOUNT_NUMBER}:endpoint/{name}"
                ),
                "ReplicationConfig": {"State": "ENABLED"},
            }

        pages = {
            "ListEndpoints": (
                {"Endpoints": [endpoint("endpoint-1")], "NextToken": "next"},
                {"Endpoints": [endpoint("endpoint-2")]},
            ),
        }

        def mock_paginated_api_call(self, operation_name, kwargs):
            if operation_name in pages:
                page_index = 1 if kwargs.get("NextToken") else 0
                return pages[operation_name][page_index]
            return mock_make_api_call(self, operation_name, kwargs)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_paginated_api_call,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            eventbridge = EventBridge(aws_provider)

        assert len(eventbridge.endpoints) == 2
        assert sorted(e.name for e in eventbridge.endpoints.values()) == [
            "endpoint-1",
            "endpoint-2",
        ]
        by_name = {e.name: e for e in eventbridge.endpoints.values()}
        assert by_name["endpoint-2"].replication_state == "ENABLED"

    # Test Schema List Registries follows pagination
    @mock_aws
    def test_list_registries_follows_next_token_pagination(self):
        def registry(name):
            return {
                "RegistryArn": (
                    f"arn:aws:schemas:{AWS_REGION_US_EAST_1}:"
                    f"{AWS_ACCOUNT_NUMBER}:registry/{name}"
                ),
                "RegistryName": name,
                "Tags": {"key1": "value1"},
            }

        pages = {
            "ListRegistries": (
                {"Registries": [registry("registry-1")], "NextToken": "next"},
                {"Registries": [registry("registry-2")]},
            ),
        }

        def mock_paginated_api_call(self, operation_name, kwargs):
            if operation_name in pages:
                page_index = 1 if kwargs.get("NextToken") else 0
                return pages[operation_name][page_index]
            return mock_make_api_call(self, operation_name, kwargs)

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_paginated_api_call,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            schema = Schema(aws_provider)

        assert len(schema.registries) == 2
        assert sorted(r.name for r in schema.registries.values()) == [
            "registry-1",
            "registry-2",
        ]
