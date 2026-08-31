from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_bedrock_agent_idle_session_ttl_not_excessive:
    @mock_aws
    def test_no_agents(self):
        """Test no agents returns empty findings."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_agent_ttl_pass_below_default(self):
        """Test PASS when TTL below default 3600."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1": Agent(
                id="agent-1",
                name="test-agent-pass",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-1",
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "env", "Value": "test"}],
                detail_retrieved=True,
                idle_session_ttl_seconds=1800,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Agent test-agent-pass idle session TTL is 1800 seconds, which does not exceed the configured maximum of 3600 seconds."
            )
            assert result[0].resource_id == "agent-1"
            assert result[0].resource_arn == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "env", "Value": "test"}]

    @mock_aws
    def test_agent_ttl_pass_exactly_default(self):
        """Test PASS when TTL exactly at 3600 boundary."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-2": Agent(
                id="agent-2",
                name="test-agent-exact",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-2",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=True,
                idle_session_ttl_seconds=3600,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_agent_ttl_fail_above_default(self):
        """Test FAIL when TTL exceeds default."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-3": Agent(
                id="agent-3",
                name="test-agent-fail",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-3",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=True,
                idle_session_ttl_seconds=3601,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Agent test-agent-fail idle session TTL is 3601 seconds, which exceeds the configured maximum of 3600 seconds."
            )
            assert result[0].resource_id == "agent-3"

    @mock_aws
    def test_custom_audit_config_override(self):
        """Test custom audit config overrides default threshold."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.audit_config = {"max_bedrock_agent_idle_session_ttl_seconds": 600}
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-4": Agent(
                id="agent-4",
                name="test-agent-custom-pass",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-4",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=True,
                idle_session_ttl_seconds=500,
            ),
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-5": Agent(
                id="agent-5",
                name="test-agent-custom-fail",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-5",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=True,
                idle_session_ttl_seconds=601,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
            assert "600 seconds" in result[0].status_extended
            assert "600 seconds" in result[1].status_extended

    @mock_aws
    def test_missing_ttl_returns_manual(self):
        """Test MANUAL when TTL missing."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-6": Agent(
                id="agent-6",
                name="test-agent-no-ttl",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-6",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=True,
                idle_session_ttl_seconds=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == "Bedrock Agent test-agent-no-ttl idle session TTL could not be determined."
            )

    @mock_aws
    def test_failed_get_agent_returns_manual_not_pass(self):
        """Test MANUAL when GetAgent failed, not PASS."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Agent, BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        bedrock_agent_client = BedrockAgent(aws_provider)
        bedrock_agent_client.agents = {
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-7": Agent(
                id="agent-7",
                name="test-agent-failed-detail",
                arn=f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:123456789012:agent/agent-7",
                region=AWS_REGION_US_EAST_1,
                tags=[],
                detail_retrieved=False,
                idle_session_ttl_seconds=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_client",
                new=bedrock_agent_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_idle_session_ttl_not_excessive.bedrock_agent_idle_session_ttl_not_excessive import (
                bedrock_agent_idle_session_ttl_not_excessive,
            )

            check = bedrock_agent_idle_session_ttl_not_excessive()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].status != "PASS"
