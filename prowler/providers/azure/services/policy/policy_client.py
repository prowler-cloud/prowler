from prowler.providers.azure.services.policy.policy_service import Policy
from prowler.providers.common.common import get_global_provider

policy_client = Policy(get_global_provider())
