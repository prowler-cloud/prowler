from typing import List

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.apim.apim_client import apim_client
from prowler.providers.azure.services.apim.apim_service import LogsQueryLogEntry


class apim_threat_detection_llm_jacking(Check):
    def execute(self):
        findings = []

        # Get configuration from audit config with defaults
        threshold = float(
            getattr(apim_client, "audit_config", {}).get(
                "apim_threat_detection_llm_jacking_threshold", 0.1
            )
        )
        threat_detection_minutes = getattr(apim_client, "audit_config", {}).get(
            "apim_threat_detection_llm_jacking_minutes", 1440
        )
        monitored_actions = getattr(apim_client, "audit_config", {}).get(
            "apim_threat_detection_llm_jacking_actions",
            [
                # OpenAI API endpoints
                "ImageGenerations_Create",
                "ChatCompletions_Create",
                "Completions_Create",
                "Embeddings_Create",
                "FineTuning_Jobs_Create",
                "Models_List",
                # Azure OpenAI endpoints
                "Deployments_List",
                "Deployments_Get",
                "Deployments_Create",
                "Deployments_Delete",
                # Anthropic endpoints
                "Messages_Create",
                "Claude_Create",
                # Google AI endpoints
                "GenerateContent",
                "GenerateText",
                "GenerateImage",
                # Meta AI endpoints
                "Llama_Create",
                "CodeLlama_Create",
                # Other LLM endpoints
                "Gemini_Generate",
                "Claude_Generate",
                "Llama_Generate",
            ],
        )

        for subscription, instances in apim_client.instances.items():
            subscription_name = apim_client.subscriptions.get(
                subscription, subscription
            )
            all_llm_logs: List[LogsQueryLogEntry] = []
            for instance in instances:
                if instance.log_analytics_workspace_id:
                    logs = apim_client.get_llm_operations_logs(
                        subscription, instance, threat_detection_minutes
                    )
                    all_llm_logs.extend(logs)

            # Analyze logs only within the current subscription to avoid
            # cross-subscription attribution when scanning multiple subscriptions.
            potential_llm_jacking_attackers = {}
            for log in all_llm_logs:
                operation_name = log.operation_id
                caller_ip = log.caller_ip_address

                if operation_name in monitored_actions and caller_ip:
                    # Use IP address as the principal identifier
                    if caller_ip not in potential_llm_jacking_attackers:
                        potential_llm_jacking_attackers[caller_ip] = set()
                    potential_llm_jacking_attackers[caller_ip].add(operation_name)

            # 3. Check each principal against the threshold and report failures
            found_potential_llm_jacking_attackers = False
            for (
                principal_ip,
                distinct_actions,
            ) in potential_llm_jacking_attackers.items():
                action_ratio = round(len(distinct_actions) / len(monitored_actions), 2)

                if action_ratio > threshold:
                    found_potential_llm_jacking_attackers = True
                    # Build Identity resource for the report
                    resource = {
                        "name": principal_ip,
                        "id": principal_ip,
                    }
                    # Report against the subscription, identifying the offending principal (IP)
                    report = Check_Report_Azure(self.metadata(), resource=resource)
                    report.subscription = subscription
                    report.status = "FAIL"
                    report.status_extended = f"Potential LLM Jacking attack detected from IP address {principal_ip} in subscription {subscription_name} ({subscription}) with an action ratio of {action_ratio}, above the configured threshold of {threshold}."
                    findings.append(report)

            # If no threats were found after checking all principals, create a single PASS report.
            if not found_potential_llm_jacking_attackers:
                report = Check_Report_Azure(self.metadata(), resource={})
                report.resource_name = subscription_name
                report.resource_id = f"/subscriptions/{subscription}"
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"No potential LLM Jacking attacks detected across monitored APIM instances in subscription {subscription_name} ({subscription}) in the last {threat_detection_minutes} minutes."
                findings.append(report)

        return findings
