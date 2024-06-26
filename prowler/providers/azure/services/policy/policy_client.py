from prowler.providers.azure.services.policy.policy_service import Policy
from prowler.providers.common.provider import Provider

policy_client = Policy(Provider.get_global_provider())
