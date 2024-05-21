from unittest import mock
from uuid import uuid4

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_bus_name = str(uuid4())
test_bus_arn = f"arn:aws:eventbridge:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/{test_bus_name}"


class Test_eventbridge_bus_exposed:
    @mock_aws
    def test_default_bus(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed import (
                eventbridge_bus_exposed,
            )

            check = eventbridge_bus_exposed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "EventBridge event bus default is not exposed to everyone."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/default"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_buses_self_account(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        events_client = client("events", region_name=AWS_REGION_EU_WEST_1)
        events_client.put_permission(
            EventBusName="default",
            Action="events:PutEvents",
            Principal=AWS_ACCOUNT_NUMBER,
            StatementId="test-statement",
        )
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed import (
                eventbridge_bus_exposed,
            )

            check = eventbridge_bus_exposed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "EventBridge event bus default is not exposed to everyone."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/default"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_buses_other_account(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        events_client = client("events", region_name=AWS_REGION_EU_WEST_1)
        events_client.put_permission(
            EventBusName="default",
            Action="events:PutEvents",
            Principal="111122223333",
            StatementId="test-statement",
        )
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed import (
                eventbridge_bus_exposed,
            )

            check = eventbridge_bus_exposed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "EventBridge event bus default is not exposed to everyone."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/default"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_buses_asterisk_principal(self):
        from prowler.providers.aws.services.eventbridge.eventbridge_service import (
            EventBridge,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        events_client = client("events", region_name=AWS_REGION_EU_WEST_1)
        events_client.put_permission(
            EventBusName="default",
            Action="events:PutEvents",
            Principal="*",
            StatementId="test-statement",
        )
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed.eventbridge_client",
            new=EventBridge(aws_provider),
        ):
            from prowler.providers.aws.services.eventbridge.eventbridge_bus_exposed.eventbridge_bus_exposed import (
                eventbridge_bus_exposed,
            )

            check = eventbridge_bus_exposed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "EventBridge event bus default is exposed to everyone."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:events:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:event-bus/default"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
