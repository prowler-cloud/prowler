from unittest import mock

import pytest
from moto import mock_aws

from prowler.providers.aws.services.bedrock.bedrock_service import Agent
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    MetricAlarm,
    MetricReference,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = (
    "prowler.providers.aws.services.cloudwatch."
    "cloudwatch_bedrock_agent_alarms_configured."
    "cloudwatch_bedrock_agent_alarms_configured"
)
_UNSET = object()


def _run_check(bedrock_agent_client, cloudwatch_client, regions=None):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(regions or [AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_PATH}.bedrock_agent_client", new=bedrock_agent_client),
        mock.patch(f"{CHECK_PATH}.cloudwatch_client", new=cloudwatch_client),
    ):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_bedrock_agent_alarms_configured.cloudwatch_bedrock_agent_alarms_configured import (
            cloudwatch_bedrock_agent_alarms_configured,
        )

        return cloudwatch_bedrock_agent_alarms_configured().execute()


def _agent(region=AWS_REGION_US_EAST_1, agent_id="agent-id"):
    return Agent(
        id=agent_id,
        name=f"test-{agent_id}",
        arn=f"arn:aws:bedrock:{region}:{AWS_ACCOUNT_NUMBER}:agent/{agent_id}",
        region=region,
    )


def _bedrock_client(agents=None, errors=None):
    client = mock.MagicMock()
    client.agents = {agent.arn: agent for agent in agents or []}
    client.agents_scan_errors = errors or {}
    return client


def _cloudwatch_client(
    alarms=_UNSET,
    scanned_regions=None,
    errors=None,
    all_alarms=_UNSET,
):
    client = mock.MagicMock()
    client.metric_alarms = [] if alarms is _UNSET else alarms
    client.all_metric_alarms = (
        client.metric_alarms if all_alarms is _UNSET else all_alarms
    )
    client.metric_alarms_scanned_regions = scanned_regions or set()
    client.metric_alarms_scan_errors = errors or {}
    client.audited_partition = "aws"
    client.audited_account = AWS_ACCOUNT_NUMBER
    return client


def _alarm(
    *,
    region=AWS_REGION_US_EAST_1,
    enabled=True,
    references=None,
):
    return MetricAlarm(
        arn=f"arn:aws:cloudwatch:{region}:{AWS_ACCOUNT_NUMBER}:alarm:agent-rate",
        name="agent-rate",
        region=region,
        alarm_actions=[],
        actions_enabled=enabled,
        metric_references=references or [],
    )


def _agent_metric(
    name="InvocationCount",
    dimensions=None,
    account_id=None,
):
    if dimensions is None:
        dimensions = {"Operation": "InvokeAgent"}
    return MetricReference(
        namespace="AWS/Bedrock/Agents",
        name=name,
        dimensions=dimensions,
        account_id=account_id,
    )


class Test_cloudwatch_bedrock_agent_alarms_configured:
    @mock_aws
    def test_direct_alarm_pass(self):
        alarm = _alarm(references=[_agent_metric()])
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client([alarm], {AWS_REGION_US_EAST_1}),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "CloudWatch has an enabled alarm for Bedrock Agent invocation or "
            f"throttling metrics in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "bedrock-agent-alarms"
        assert result[0].resource_arn == (
            f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:" f"{AWS_ACCOUNT_NUMBER}:alarm"
        )

    @mock_aws
    def test_metric_math_alarm_pass(self):
        alarm = _alarm(references=[_agent_metric("InvocationThrottles")])

        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client([alarm], {AWS_REGION_US_EAST_1}),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    @pytest.mark.parametrize(
        ("enabled", "references"),
        [
            (
                False,
                [
                    MetricReference(
                        namespace="AWS/Bedrock/Agents",
                        name="InvocationCount",
                    )
                ],
            ),
            (
                True,
                [MetricReference(namespace="AWS/Bedrock/Agents", name="TotalTime")],
            ),
            (
                True,
                [MetricReference(namespace="Custom/App", name="InvocationCount")],
            ),
            (
                True,
                [
                    MetricReference(namespace="AWS/Bedrock/Agents", name="TotalTime"),
                    MetricReference(namespace="Custom/App", name="InvocationCount"),
                ],
            ),
            (
                True,
                [
                    MetricReference(
                        namespace="AWS/Bedrock/Agents",
                        name="ModelInvocationCount",
                    )
                ],
            ),
        ],
    )
    @mock_aws
    def test_unqualified_alarm_fail(self, enabled, references):
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(
                [_alarm(enabled=enabled, references=references)],
                {AWS_REGION_US_EAST_1},
            ),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @pytest.mark.parametrize(
        "reference",
        [
            MetricReference(namespace="AWS/Bedrock/Agents", name="InvocationCount"),
            _agent_metric(dimensions={"Operation": "FakeOperation"}),
            _agent_metric(
                dimensions={"Operation": "InvokeAgent", "ModelId": "model-id"}
            ),
            _agent_metric(account_id="111122223333"),
        ],
    )
    @mock_aws
    def test_wrong_metric_identity_fail(self, reference):
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(
                [_alarm(references=[reference])],
                {AWS_REGION_US_EAST_1},
            ),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @pytest.mark.parametrize(
        "reference",
        [
            _agent_metric(dimensions={"Operation": "InvokeInlineAgent"}),
            _agent_metric(account_id=AWS_ACCOUNT_NUMBER),
            _agent_metric(
                dimensions={
                    "Operation": "InvokeAgent",
                    "AgentAliasArn": "arn:aws:bedrock:us-east-1:123456789012:agent-alias/agent/alias",
                    "ModelId": "model-id",
                }
            ),
        ],
    )
    @mock_aws
    def test_valid_metric_identity_pass(self, reference):
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(
                [_alarm(references=[reference])],
                {AWS_REGION_US_EAST_1},
            ),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_no_agents_no_findings(self):
        result = _run_check(
            _bedrock_client(),
            _cloudwatch_client(scanned_regions={AWS_REGION_US_EAST_1}),
        )

        assert result == []

    @mock_aws
    def test_no_qualifying_alarm_fail(self):
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(scanned_regions={AWS_REGION_US_EAST_1}),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "CloudWatch has no enabled alarms for Bedrock Agent invocation or "
            f"throttling metrics in region {AWS_REGION_US_EAST_1}."
        )

    @mock_aws
    def test_regions_are_checked_separately(self):
        alarm = _alarm(
            region=AWS_REGION_US_EAST_1,
            references=[_agent_metric()],
        )
        agents = [
            _agent(agent_id="east-a"),
            _agent(agent_id="east-b"),
            _agent(region=AWS_REGION_EU_WEST_1, agent_id="west"),
        ]

        result = _run_check(
            _bedrock_client(agents),
            _cloudwatch_client(
                [alarm],
                {AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1},
            ),
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
        )

        assert [(item.region, item.status) for item in result] == [
            (AWS_REGION_EU_WEST_1, "FAIL"),
            (AWS_REGION_US_EAST_1, "PASS"),
        ]

    @mock_aws
    def test_filtered_agent_uses_full_alarm_inventory(self):
        alarm = _alarm(references=[_agent_metric()])
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(
                [],
                {AWS_REGION_US_EAST_1},
                all_alarms=[alarm],
            ),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_cloudwatch_error_is_manual(self):
        alarm = _alarm(references=[_agent_metric()])
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(
                [alarm],
                errors={AWS_REGION_US_EAST_1: "AccessDenied"},
            ),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Bedrock Agent alarm coverage in region "
            f"{AWS_REGION_US_EAST_1}: cloudwatch:DescribeAlarms returned "
            "AccessDenied. Check API access and retry the scan."
        )

    @mock_aws
    def test_bedrock_error_is_manual(self):
        result = _run_check(
            _bedrock_client(errors={AWS_REGION_US_EAST_1: "AccessDeniedException"}),
            _cloudwatch_client(scanned_regions={AWS_REGION_US_EAST_1}),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Bedrock Agent alarm coverage in region "
            f"{AWS_REGION_US_EAST_1}: bedrock:ListAgents returned "
            "AccessDeniedException. Check API access and retry the scan."
        )

    @mock_aws
    def test_partial_bedrock_error_overrides_alarm(self):
        alarm = _alarm(references=[_agent_metric()])
        result = _run_check(
            _bedrock_client(
                [_agent()],
                {AWS_REGION_US_EAST_1: "ThrottlingException"},
            ),
            _cloudwatch_client([alarm], {AWS_REGION_US_EAST_1}),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_cloudwatch_error_without_agents_has_no_findings(self):
        result = _run_check(
            _bedrock_client(),
            _cloudwatch_client(errors={AWS_REGION_US_EAST_1: "AccessDenied"}),
        )

        assert result == []

    @mock_aws
    def test_unscanned_cloudwatch_region_is_manual(self):
        result = _run_check(
            _bedrock_client([_agent()]),
            _cloudwatch_client(),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Bedrock Agent alarm coverage in region "
            f"{AWS_REGION_US_EAST_1}: CloudWatch alarms were not scanned."
        )

    @mock_aws
    def test_legacy_unavailable_inventory_stays_regional(self):
        result = _run_check(
            _bedrock_client(
                [
                    _agent(),
                    _agent(region=AWS_REGION_EU_WEST_1, agent_id="west"),
                ]
            ),
            _cloudwatch_client(
                None,
                scanned_regions={AWS_REGION_EU_WEST_1},
                errors={AWS_REGION_US_EAST_1: "AccessDenied"},
            ),
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
        )

        assert [(item.region, item.status) for item in result] == [
            (AWS_REGION_EU_WEST_1, "FAIL"),
            (AWS_REGION_US_EAST_1, "MANUAL"),
        ]
