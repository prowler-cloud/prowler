"""Tests that drive the vended-log delivery collectors, not the models they fill.

A check test that assigns `logs_client.delivery_sources` directly proves the check's
logic and nothing about the response keys the collector reads. A renamed key would
leave every such test green while the collector returned nothing against a real
account. These tests patch the API call instead, so the response key names and the
unreadable-inventory sentinel are what is under assertion.
"""

from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

CHECK_NAME = "bedrockagentcore_gateway_application_logs_enabled"

GW_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/ABCDE12345"
MEMORY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/mem-ABCDE12345"
SOURCE_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-source:gateway-logs-source"
DESTINATION_ARN = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery-destination:gateway-logs-destination"
DELIVERY_ARN = (
    f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:delivery:AbCdEf123456"
)

# Verbatim DescribeDeliverySources / DescribeDeliveries members, in the casing the
# API returns them: the collector reading a different spelling is the defect these
# tests exist to catch.
APPLICATION_LOGS_SOURCE = {
    "name": "gateway-logs-source",
    "arn": SOURCE_ARN,
    "resourceArns": [GW_ARN],
    "service": "bedrock-agentcore",
    "logType": "APPLICATION_LOGS",
}
TRACES_SOURCE = {
    "name": "gateway-traces-source",
    "arn": f"{SOURCE_ARN}-traces",
    "resourceArns": [GW_ARN],
    "service": "bedrock-agentcore",
    "logType": "TRACES",
}
MEMORY_SOURCE = {
    "name": "memory-logs-source",
    "arn": f"{SOURCE_ARN}-memory",
    "resourceArns": [MEMORY_ARN],
    "service": "bedrock-agentcore",
    "logType": "APPLICATION_LOGS",
}
DELIVERY = {
    "id": "AbCdEf123456",
    "arn": DELIVERY_ARN,
    "deliverySourceName": "gateway-logs-source",
    "deliveryDestinationArn": DESTINATION_ARN,
    "deliveryDestinationType": "CWL",
}


def _mock(
    sources=(),
    deliveries=(),
    denied=(),
    denied_region=None,
    deny_second_page=(),
    pages=False,
):
    """Build a _make_api_call replacement for the two delivery operations.

    moto answers both operations with an empty list whatever the account holds, so
    it cannot drive this collector at all.

    Args:
        sources: DescribeDeliverySources items to return.
        deliveries: DescribeDeliveries items to return.
        denied: operation names that raise AccessDeniedException.
        denied_region: when set, only that Region's calls raise, so per-Region
            independence is asserted rather than assumed.
        deny_second_page: operation names whose first page succeeds and whose
            second page raises, which is the partial-inventory case.
        pages: split each list across two pages to exercise the paginator.
    """

    def _make_call(self, operation_name, kwarg):
        region = self.meta.region_name
        paging = bool(kwarg.get("nextToken"))
        if (operation_name in denied and denied_region in (None, region)) or (
            operation_name in deny_second_page and paging
        ):
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                operation_name,
            )
        member_and_items = {
            "DescribeDeliverySources": ("deliverySources", list(sources)),
            "DescribeDeliveries": ("deliveries", list(deliveries)),
        }.get(operation_name)
        if member_and_items is None:
            return make_api_call(self, operation_name, kwarg)
        member, items = member_and_items
        if pages and items:
            # nextToken is echoed back by the paginator, so a collector that
            # reads only the first page loses everything after it.
            if not paging:
                return {member: items[:1], "nextToken": "page-2"}
            return {member: items[1:]}
        return {member: items}

    return _make_call


def _logs(regions=(AWS_REGION_US_EAST_1,)):
    """Build the Logs service with the delivery collectors in scope."""
    aws_provider = set_mocked_aws_provider(
        audited_regions=list(regions), expected_checks=[CHECK_NAME]
    )
    return Logs(aws_provider)


class Test_Logs_Delivery_Collectors:
    """Tests for _describe_delivery_sources and _describe_deliveries."""

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(sources=[APPLICATION_LOGS_SOURCE, TRACES_SOURCE, MEMORY_SOURCE]),
    )
    @mock_aws
    def test_delivery_source_fields_are_collected(self):
        """Every field a caller joins on survives the collector verbatim."""
        logs = _logs()

        sources = logs.delivery_sources[AWS_REGION_US_EAST_1]
        assert len(sources) == 3
        application_logs, traces, memory = sources
        assert application_logs.name == "gateway-logs-source"
        assert application_logs.arn == SOURCE_ARN
        assert application_logs.resource_arns == [GW_ARN]
        assert application_logs.service == "bedrock-agentcore"
        assert application_logs.log_type == "APPLICATION_LOGS"
        assert application_logs.region == AWS_REGION_US_EAST_1
        # The log type distinguishes the call trail from the spans, and the
        # resource ARN distinguishes a gateway's source from a memory's, so both
        # must arrive intact for either filter to mean anything.
        assert traces.log_type == "TRACES"
        assert memory.resource_arns == [MEMORY_ARN]

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(sources=[APPLICATION_LOGS_SOURCE], deliveries=[DELIVERY]),
    )
    @mock_aws
    def test_delivery_fields_are_collected(self):
        """deliverySourceName arrives intact, so a delivery links to its source."""
        logs = _logs()

        deliveries = logs.deliveries[AWS_REGION_US_EAST_1]
        assert len(deliveries) == 1
        delivery = deliveries[0]
        assert delivery.id == "AbCdEf123456"
        assert delivery.arn == DELIVERY_ARN
        assert delivery.delivery_source_name == "gateway-logs-source"
        assert delivery.delivery_destination_arn == DESTINATION_ARN
        assert delivery.delivery_destination_type == "CWL"
        assert delivery.region == AWS_REGION_US_EAST_1
        # The link is by name, the only field the two objects share.
        assert delivery.delivery_source_name == (
            logs.delivery_sources[AWS_REGION_US_EAST_1][0].name
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            sources=[{"name": "no-resources-source", "logType": "APPLICATION_LOGS"}]
        ),
    )
    @mock_aws
    def test_source_without_resource_arns_collects_an_empty_list(self):
        """Every DeliverySource member is optional, so absence must not be None.

        A None here would raise inside the `gateway.arn in source.resource_arns`
        join rather than simply matching nothing.
        """
        source = _logs().delivery_sources[AWS_REGION_US_EAST_1][0]

        assert source.resource_arns == []
        assert source.arn == ""
        assert source.log_type == "APPLICATION_LOGS"

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            sources=[APPLICATION_LOGS_SOURCE, TRACES_SOURCE],
            deliveries=[DELIVERY, {**DELIVERY, "id": "second", "arn": "second-arn"}],
            pages=True,
        ),
    )
    @mock_aws
    def test_every_page_is_collected(self):
        """A second page is read; a truncated inventory reads as not-configured."""
        logs = _logs()

        assert [
            source.log_type for source in logs.delivery_sources[AWS_REGION_US_EAST_1]
        ] == [
            "APPLICATION_LOGS",
            "TRACES",
        ]
        assert [delivery.id for delivery in logs.deliveries[AWS_REGION_US_EAST_1]] == [
            "AbCdEf123456",
            "second",
        ]

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            sources=[APPLICATION_LOGS_SOURCE],
            deliveries=[DELIVERY],
            denied=["DescribeDeliverySources"],
            denied_region=AWS_REGION_US_EAST_1,
        ),
    )
    @mock_aws
    def test_denied_delivery_sources_store_none_not_an_empty_list(self):
        """An unlistable inventory is unknown, and only in its own Region.

        An empty list would read as "no delivery source configured" and turn a
        missing permission into a FAIL against a compliant gateway.
        """
        logs = _logs(regions=(AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1))

        assert logs.delivery_sources[AWS_REGION_US_EAST_1] is None
        assert logs.delivery_sources[AWS_REGION_US_EAST_1] != []
        # The failure is attributed to one Region and one inventory: the other
        # Region and the deliveries listing are still definite answers.
        assert len(logs.delivery_sources[AWS_REGION_EU_WEST_1]) == 1
        assert len(logs.deliveries[AWS_REGION_US_EAST_1]) == 1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            sources=[APPLICATION_LOGS_SOURCE],
            deliveries=[DELIVERY],
            denied=["DescribeDeliveries"],
            denied_region=AWS_REGION_US_EAST_1,
        ),
    )
    @mock_aws
    def test_denied_deliveries_store_none_not_an_empty_list(self):
        """A readable source list does not make an unreadable delivery list empty."""
        logs = _logs(regions=(AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1))

        assert logs.deliveries[AWS_REGION_US_EAST_1] is None
        assert logs.deliveries[AWS_REGION_US_EAST_1] != []
        assert len(logs.deliveries[AWS_REGION_EU_WEST_1]) == 1
        assert len(logs.delivery_sources[AWS_REGION_US_EAST_1]) == 1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock(
            sources=[APPLICATION_LOGS_SOURCE, TRACES_SOURCE],
            deliveries=[DELIVERY],
            deny_second_page=["DescribeDeliverySources"],
            pages=True,
        ),
    )
    @mock_aws
    def test_a_failure_mid_pagination_discards_the_partial_inventory(self):
        """Half an inventory is not a smaller inventory, it is an unknown one.

        The first page succeeds and the second is denied, so a collector that
        accumulated into the shared store would leave one real source visible and
        the rest missing -- reported as a definite answer.
        """
        logs = _logs()

        assert logs.delivery_sources[AWS_REGION_US_EAST_1] is None
        # The other listing paginated to completion, so it stays definite.
        assert [delivery.id for delivery in logs.deliveries[AWS_REGION_US_EAST_1]] == [
            "AbCdEf123456"
        ]
