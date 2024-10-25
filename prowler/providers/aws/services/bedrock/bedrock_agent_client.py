from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent
from prowler.providers.common.provider import Provider

bedrock_agent_client = BedrockAgent(Provider.get_global_provider())
