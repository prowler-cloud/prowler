from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)
from prowler.providers.azure.services.aiservices.aiservices_service import (
    Deployment,
    RaiPolicy,
)

# Deployment capabilities that take text prompts, where Prompt Shields applies.
TEXT_GENERATION_CAPABILITIES = {
    "chatcompletion",
    "completion",
    "responses",
    "assistants",
}


class aiservices_deployment_content_filter_prompt_shield_enabled(Check):
    """AI services deployment blocks jailbreak attempts with Prompt Shields."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the content filter policy of every model deployment.

        PASS when the deployment's policy has the `Jailbreak` filter enabled
        and blocking on prompts. MANUAL when the deployment uses the account
        default policy (empty `raiPolicyName`), because Azure does not say
        which policy that is, or when the policy cannot be read.

        Deployments whose capabilities show no text generation (embeddings,
        transcription, image generation) are skipped. Deployments that report
        no capabilities are evaluated.

        Returns:
            One finding per evaluated deployment, plus one MANUAL finding per account
            whose deployments cannot be read.
        """
        findings = []
        for subscription_id, accounts in aiservices_client.accounts.items():
            subscription_name = aiservices_client.subscriptions.get(
                subscription_id, subscription_id
            )
            subscription = f"subscription {subscription_name} ({subscription_id})"
            for account in accounts.values():
                if account.deployments is None:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=account
                    )
                    report.subscription = subscription_id
                    report.status = "MANUAL"
                    report.status_extended = f"Deployments of AI services account {account.name} (kind {account.kind}) from {subscription} could not be read."
                    findings.append(report)
                    continue
                # ARM resource names are case-insensitive.
                rai_policies = (
                    None
                    if account.rai_policies is None
                    else {
                        name.lower(): policy
                        for name, policy in account.rai_policies.items()
                    }
                )
                for deployment in account.deployments:
                    if not _takes_text_prompts(deployment):
                        continue
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=deployment
                    )
                    report.subscription = subscription_id
                    prefix = f"AI services deployment {deployment.name} (model {deployment.model_name}) in account {account.name} from {subscription}"
                    policy_name = deployment.rai_policy_name
                    if not policy_name:
                        report.status = "MANUAL"
                        report.status_extended = f"{prefix} uses the account default content filter policy, which Azure does not identify. Confirm that it blocks jailbreak attempts with Prompt Shields."
                    elif rai_policies is None:
                        report.status = "MANUAL"
                        report.status_extended = f"{prefix} uses content filter policy {policy_name}, which could not be read."
                    elif policy_name.lower() not in rai_policies:
                        report.status = "MANUAL"
                        report.status_extended = f"{prefix} uses content filter policy {policy_name}, which was not found on the account."
                    elif _blocks_jailbreak(rai_policies[policy_name.lower()]):
                        report.status = "PASS"
                        report.status_extended = f"{prefix} uses content filter policy {policy_name}, which blocks jailbreak attempts with Prompt Shields."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"{prefix} uses content filter policy {policy_name}, which does not block jailbreak attempts with Prompt Shields."
                    findings.append(report)
        return findings


def _takes_text_prompts(deployment: Deployment) -> bool:
    """Return whether a deployment serves a model that takes text prompts."""
    if not deployment.capabilities:
        return True
    return any(
        name.lower() in TEXT_GENERATION_CAPABILITIES and str(value).lower() == "true"
        for name, value in deployment.capabilities.items()
    )


def _blocks_jailbreak(policy: RaiPolicy) -> bool:
    """Return whether a policy blocks jailbreak attempts on prompts."""
    return any(
        content_filter.name.lower() == "jailbreak"
        and content_filter.source.lower() == "prompt"
        and content_filter.enabled
        and content_filter.blocking
        for content_filter in policy.content_filters
    )
