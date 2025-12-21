"""
Tests for Bedrock Service Pagination.
"""
from unittest.mock import MagicMock
from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock, BedrockAgent


class TestBedrockPagination:
    """Test suite for Bedrock Guardrail pagination logic."""

    def test_list_guardrails_pagination(self):
        """Test that list_guardrails iterates through all pages."""
        # Mock the audit_info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock the regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock pagination responses
        page1 = {
            "guardrails": [
                {
                    "id": "g-1",
                    "name": "guardrail-1",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-1",
                }
            ],
            "nextToken": "token-2",
        }
        page2 = {
            "guardrails": [
                {
                    "id": "g-2",
                    "name": "guardrail-2",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-2",
                }
            ]
            # No nextToken implies end of results
        }

        regional_client.list_guardrails.side_effect = [page1, page2]

        # Initialize service and inject mock client
        bedrock_service = Bedrock(audit_info)
        bedrock_service.regional_clients = {"us-east-1": regional_client}
        bedrock_service.guardrails = {}  # Clear any init side effects

        # Run the method under test
        bedrock_service._list_guardrails(regional_client)

        # Assertions
        assert len(bedrock_service.guardrails) == 2
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-1"
            in bedrock_service.guardrails
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-2"
            in bedrock_service.guardrails
        )

        # Verify calls
        assert regional_client.list_guardrails.call_count == 2
        regional_client.list_guardrails.assert_any_call()
        regional_client.list_guardrails.assert_any_call(nextToken="token-2")


class TestBedrockAgentPagination:
    """Test suite for Bedrock Agent pagination logic."""

    def test_list_agents_pagination(self):
        """Test that list_agents iterates through all pages."""
        # Mock the audit_info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock the regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock pagination responses
        page1 = {
            "agentSummaries": [
                {
                    "agentId": "agent-1",
                    "agentName": "agent-name-1",
                    "agentStatus": "PREPARED",
                }
            ],
            "nextToken": "token-2",
        }
        page2 = {
            "agentSummaries": [
                {
                    "agentId": "agent-2",
                    "agentName": "agent-name-2",
                    "agentStatus": "PREPARED",
                }
            ]
        }

        regional_client.list_agents.side_effect = [page1, page2]

        # Initialize service and inject mock client
        # BedrockAgent service initializes listing in __init__, so we need to be careful
        # Ideally we'd patch the method before init if we were mocking the whole class,
        # but here we can just test the method directly if we instantiate carefully.

        # However, since __init__ calls __threading_call__ which calls _list_agents,
        # let's simpler test the method by calling it manually after a rough init.

        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.agents = {}  # Clear init side effects

        bedrock_agent_service.audited_account = "123456789012"
        # Run method
        bedrock_agent_service._list_agents(regional_client)

        # Assertions
        assert len(bedrock_agent_service.agents) == 2
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1"
            in bedrock_agent_service.agents
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-2"
            in bedrock_agent_service.agents
        )

        # Verify calls
        assert regional_client.list_agents.call_count == 2
        regional_client.list_agents.assert_any_call()
        regional_client.list_agents.assert_any_call(nextToken="token-2")
