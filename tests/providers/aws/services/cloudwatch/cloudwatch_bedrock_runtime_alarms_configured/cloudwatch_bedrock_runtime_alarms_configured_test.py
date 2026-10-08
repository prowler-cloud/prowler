from unittest import mock

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.cloudwatch.cloudwatch_bedrock_runtime_alarms_configured.cloudwatch_bedrock_runtime_alarms_configured"

# The check module instantiates the bedrock_client/bedrock_agent_client/cloudwatch_client
# singletons at import time, so a provider must exist in the global slot for that first
# import. Every test below then overrides those singletons with its own MagicMocks.
with mock.patch(
    "prowler.providers.common.provider.Provider.get_global_provider",
    return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
):
    from prowler.providers.aws.services.cloudwatch.cloudwatch_bedrock_runtime_alarms_configured.cloudwatch_bedrock_runtime_alarms_configured import (
        cloudwatch_bedrock_runtime_alarms_configured,
    )


def _bedrock_client(guardrails=None, custom_models=None, logging_configurations=None):
    client = mock.MagicMock()
    client.guardrails = guardrails or {}
    client.custom_models = custom_models or {}
    client.logging_configurations = logging_configurations or {}
    return client


def _bedrock_agent_client(agents=None, knowledge_bases=None, prompts=None):
    client = mock.MagicMock()
    client.agents = agents or {}
    client.knowledge_bases = knowledge_bases or {}
    client.prompts = prompts or {}
    return client


def _cloudwatch_client(metric_alarms):
    client = mock.MagicMock()
    client.metric_alarms = metric_alarms
    client.audited_partition = "aws"
    client.audited_account = AWS_ACCOUNT_NUMBER
    return client


class Test_cloudwatch_bedrock_runtime_alarms_configured:
    def test_no_bedrock_resources_no_findings(self):
        """No Bedrock resources anywhere: the check has nothing in scope."""
        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert result == []

    def test_bedrock_resources_no_alarm_fails(self):
        """A guardrail exists in-region but no CloudWatch alarm covers Bedrock."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Guardrail

        guardrail = Guardrail(
            id="test-id",
            name="test-guardrail",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id",
            region=AWS_REGION_US_EAST_1,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(guardrails={guardrail.arn: guardrail}),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "bedrock-runtime-alarms"
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm"
            )
            assert "No enabled CloudWatch alarm" in result[0].status_extended

    def test_direct_namespace_alarm_passes(self):
        """A single-metric alarm on the AWS/Bedrock namespace covers the region."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Guardrail
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            MetricAlarm,
        )

        guardrail = Guardrail(
            id="test-id",
            name="test-guardrail",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id",
            region=AWS_REGION_US_EAST_1,
        )
        alarm = MetricAlarm(
            arn=f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test",
            name="test",
            metric="Invocations",
            name_space="AWS/Bedrock",
            namespaces=["AWS/Bedrock"],
            region=AWS_REGION_US_EAST_1,
            alarm_actions=["arn:aws:sns:us-east-1:123456789012:topic"],
            actions_enabled=True,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(guardrails={guardrail.arn: guardrail}),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([alarm]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert "At least one enabled CloudWatch alarm" in result[0].status_extended

    def test_metric_math_alarm_passes(self):
        """A metric-math alarm whose component metric is AWS/Bedrock also counts."""
        from prowler.providers.aws.services.bedrock.bedrock_service import (
            LoggingConfiguration,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            MetricAlarm,
        )

        alarm = MetricAlarm(
            arn=f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:math-alarm",
            name="math-alarm",
            metric=None,
            name_space=None,
            namespaces=["AWS/Bedrock"],
            region=AWS_REGION_US_EAST_1,
            alarm_actions=["arn:aws:sns:us-east-1:123456789012:topic"],
            actions_enabled=True,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(
                    logging_configurations={
                        AWS_REGION_US_EAST_1: LoggingConfiguration(enabled=True)
                    }
                ),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([alarm]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_disabled_alarm_actions_do_not_count(self):
        """An alarm on AWS/Bedrock whose actions are disabled is not coverage."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            MetricAlarm,
        )

        agent = Agent(
            id="agent-id",
            name="test-agent",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:agent/agent-id",
            region=AWS_REGION_US_EAST_1,
        )
        alarm = MetricAlarm(
            arn=f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test",
            name="test",
            metric="Invocations",
            name_space="AWS/Bedrock",
            namespaces=["AWS/Bedrock"],
            region=AWS_REGION_US_EAST_1,
            alarm_actions=[],
            actions_enabled=False,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(agents={agent.arn: agent}),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([alarm]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_alarm_on_unrelated_namespace_fails(self):
        """An enabled alarm that does not reference AWS/Bedrock is not coverage."""
        from prowler.providers.aws.services.bedrock.bedrock_service import (
            CustomModel,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            MetricAlarm,
        )

        model = CustomModel(
            name="test-model",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:custom-model/test-model",
            region=AWS_REGION_US_EAST_1,
        )
        alarm = MetricAlarm(
            arn=f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test",
            name="test",
            metric="CPUUtilization",
            name_space="AWS/EC2",
            namespaces=["AWS/EC2"],
            region=AWS_REGION_US_EAST_1,
            alarm_actions=["arn:aws:sns:us-east-1:123456789012:topic"],
            actions_enabled=True,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(custom_models={model.arn: model}),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([alarm]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_alarms_could_not_be_listed_is_manual(self):
        """cloudwatch_client.metric_alarms is None when DescribeAlarms failed."""
        from prowler.providers.aws.services.bedrock.bedrock_service import (
            KnowledgeBase,
        )

        knowledge_base = KnowledgeBase(
            id="kb-id",
            name="test-kb",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:knowledge-base/kb-id",
            region=AWS_REGION_US_EAST_1,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(
                    knowledge_bases={knowledge_base.arn: knowledge_base}
                ),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client(None),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be listed" in result[0].status_extended

    def test_multi_region_mixed_results(self):
        """One region passes, one fails, and a Bedrock-free region is absent."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Guardrail
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            MetricAlarm,
        )

        guardrail_us = Guardrail(
            id="test-id-us",
            name="us-guardrail",
            arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id-us",
            region=AWS_REGION_US_EAST_1,
        )
        guardrail_eu = Guardrail(
            id="test-id-eu",
            name="eu-guardrail",
            arn=f"arn:aws:bedrock:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id-eu",
            region=AWS_REGION_EU_WEST_1,
        )
        covering_alarm = MetricAlarm(
            arn=f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test",
            name="test",
            metric="Invocations",
            name_space="AWS/Bedrock",
            namespaces=["AWS/Bedrock"],
            region=AWS_REGION_US_EAST_1,
            alarm_actions=["arn:aws:sns:us-east-1:123456789012:topic"],
            actions_enabled=True,
        )
        # An alarm in a third region with no Bedrock resources: must not appear.
        unrelated_region_alarm = MetricAlarm(
            arn="arn:aws:cloudwatch:ap-southeast-1:123456789012:alarm:unrelated",
            name="unrelated",
            metric="Invocations",
            name_space="AWS/Bedrock",
            namespaces=["AWS/Bedrock"],
            region="ap-southeast-1",
            alarm_actions=["arn:aws:sns:ap-southeast-1:123456789012:topic"],
            actions_enabled=True,
        )

        with (
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=_bedrock_client(
                    guardrails={
                        guardrail_us.arn: guardrail_us,
                        guardrail_eu.arn: guardrail_eu,
                    }
                ),
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_agent_client",
                new=_bedrock_agent_client(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.cloudwatch_client",
                new=_cloudwatch_client([covering_alarm, unrelated_region_alarm]),
            ),
        ):

            check = cloudwatch_bedrock_runtime_alarms_configured()
            result = check.execute()

            assert len(result) == 2
            results_by_region = {r.region: r for r in result}
            assert results_by_region[AWS_REGION_US_EAST_1].status == "PASS"
            assert results_by_region[AWS_REGION_EU_WEST_1].status == "FAIL"
            assert "ap-southeast-1" not in results_by_region
