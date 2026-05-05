from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege import (
    bedrock_agent_role_least_privilege,
)
from prowler.providers.aws.services.bedrock.bedrock_service import Agent

AGENT_ID = "test-agent-id"
AGENT_NAME = "test-agent"
AGENT_ARN = "arn:aws:bedrock:us-east-1:123456789012:agent/test-agent-id"
ROLE_ARN = "arn:aws:iam::123456789012:role/TestAgentRole"
ROLE_NAME = "TestAgentRole"
REGION = "us-east-1"


def make_agent(role_arn=ROLE_ARN):
    return Agent(
        id=AGENT_ID,
        name=AGENT_NAME,
        arn=AGENT_ARN,
        region=REGION,
        agent_resource_role_arn=role_arn,
    )


class TestBedrockAgentRoleLeastPrivilege:

    def test_pass_no_full_access_policies(self):
        mock_role = MagicMock()
        mock_role.attached_policies = [
            {"PolicyName": "ScopedPolicy", "PolicyArn": "arn:aws:iam::123456789012:policy/ScopedPolicy"}
        ]

        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ) as mock_iam:
            mock_bedrock.agents = {AGENT_ARN: make_agent()}
            mock_iam.roles = {ROLE_NAME: mock_role}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert ROLE_NAME in findings[0].status_extended

    def test_fail_full_access_policy_attached(self):
        mock_role = MagicMock()
        mock_role.attached_policies = [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        ]

        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ) as mock_iam:
            mock_bedrock.agents = {AGENT_ARN: make_agent()}
            mock_iam.roles = {ROLE_NAME: mock_role}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "AdministratorAccess" in findings[0].status_extended

    def test_fail_no_execution_role(self):
        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ):
            mock_bedrock.agents = {AGENT_ARN: make_agent(role_arn=None)}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "no execution role" in findings[0].status_extended

    def test_fail_bedrock_full_access_policy(self):
        mock_role = MagicMock()
        mock_role.attached_policies = [
            {
                "PolicyName": "AmazonBedrockFullAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
            }
        ]

        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ) as mock_iam:
            mock_bedrock.agents = {AGENT_ARN: make_agent()}
            mock_iam.roles = {ROLE_NAME: mock_role}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "AmazonBedrockFullAccess" in findings[0].status_extended

    def test_pass_no_attached_policies(self):
        mock_role = MagicMock()
        mock_role.attached_policies = []

        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ) as mock_iam:
            mock_bedrock.agents = {AGENT_ARN: make_agent()}
            mock_iam.roles = {ROLE_NAME: mock_role}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_no_agents(self):
        with patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client"
        ) as mock_bedrock, patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client"
        ):
            mock_bedrock.agents = {}

            check = bedrock_agent_role_least_privilege()
            findings = check.execute()

            assert len(findings) == 0