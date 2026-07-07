from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class DLM(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.lifecycle_policies = {}
        self.regions_with_snapshots = {}
        self.__threading_call__(self._get_lifecycle_policies)
        ec2_regional_clients = provider.generate_regional_clients("ec2") or {}
        self.__threading_call__(
            self._get_regions_with_snapshots,
            iterator=ec2_regional_clients.values(),
        )

    def _get_lifecycle_policy_arn_template(self, region):
        return (
            f"arn:{self.audited_partition}:dlm:{region}:{self.audited_account}:policy"
        )

    def _get_lifecycle_policies(self, regional_client):
        logger.info("DLM - Getting EBS Snapshots Lifecycle Policies...")
        try:
            lifecycle_policies = regional_client.get_lifecycle_policies()
            policies = {}
            for policy in lifecycle_policies["Policies"]:
                policy_id = policy.get("PolicyId")
                policies[policy_id] = LifecyclePolicy(
                    id=policy_id,
                    state=policy.get("State"),
                    tags=policy.get("Tags"),
                    type=policy.get("PolicyType"),
                )
            self.lifecycle_policies[regional_client.region] = policies
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_regions_with_snapshots(self, regional_client):
        logger.info("DLM - Checking regions with self-owned EBS snapshots...")
        try:
            self.regions_with_snapshots[regional_client.region] = False
            next_token = None
            while True:
                describe_snapshots_args = {
                    "OwnerIds": ["self"],
                    "MaxResults": 5,
                }
                if next_token:
                    describe_snapshots_args["NextToken"] = next_token

                snapshots = regional_client.describe_snapshots(
                    **describe_snapshots_args
                )
                if snapshots.get("Snapshots"):
                    self.regions_with_snapshots[regional_client.region] = True
                    break

                next_token = snapshots.get("NextToken")
                if not next_token:
                    break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class LifecyclePolicy(BaseModel):
    id: str
    state: str
    tags: dict
    type: str
