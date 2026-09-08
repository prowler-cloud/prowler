from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    BedrockAgentCore,
)
from prowler.providers.common.provider import Provider

bedrockagentcore_client = BedrockAgentCore(Provider.get_global_provider())
