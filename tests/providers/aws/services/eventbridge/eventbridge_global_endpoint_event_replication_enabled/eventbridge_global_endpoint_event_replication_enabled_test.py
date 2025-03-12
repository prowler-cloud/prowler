from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListEndpoints":
        return {
            "Endpoints": [
                {
                    "Name": "test-endpoint-disabled",
                    "Arn": f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint-disabled",
                    "ReplicationConfig": {"State": "DISABLED"},
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListEndpoints":
        return {
            "Endpoints": [
                {
                    "Name": "test-endpoint-enabled",
                    "Arn": f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint-enabled",
                    "ReplicationConfig": {"State": "ENABLED"},
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


class Test_eventbridge_global_endpoint_event_replication_enabled:
    @mock_aws
    def test_no_endpoints(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled import (
                eventbridge_global_endpoint_event_replication_enabled,
            )

            check = eventbridge_global_endpoint_event_replication_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_replication_disabled(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled import (
                eventbridge_global_endpoint_event_replication_enabled,
            )

            check = eventbridge_global_endpoint_event_replication_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "EventBridge global endpoint test-endpoint-disabled does not have event replication enabled."
            )
            assert result[0].resource_id == "test-endpoint-disabled"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint-disabled"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_replication_enabled(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled import (
                eventbridge_global_endpoint_event_replication_enabled,
            )

            check = eventbridge_global_endpoint_event_replication_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "EventBridge global endpoint test-endpoint-enabled has event replication enabled."
            )
            assert result[0].resource_id == "test-endpoint-enabled"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint/test-endpoint-enabled"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
