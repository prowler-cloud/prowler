# prowler/contrib/aws/simulate_policy_client.py
from typing import Optional

from prowler.contrib.aws.simulate_policy.simulate_policy_service import IamSimulator
from prowler.providers.common.provider import Provider

_iam_simulator_client: Optional[IamSimulator] = None


def get_iam_simulator_client() -> IamSimulator:
    global _iam_simulator_client
    if _iam_simulator_client is None:
        provider = Provider.get_global_provider()
        if provider is None:
            # Fail fast with a clear message if somehow called too early
            raise RuntimeError(
                "Global Provider is not initialized yet for IAM simulator."
            )
        _iam_simulator_client = IamSimulator(provider)
    return _iam_simulator_client
