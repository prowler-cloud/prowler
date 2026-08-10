from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_workload_identity_pool_provider_attribute_condition(Check):
    """Ensure Workload Identity Federation providers enforce an attribute condition.

    A workload identity pool provider without an ``attributeCondition`` accepts
    every external identity issued by the configured issuer or AWS account. An
    attacker who can add or edit a provider can then trust an identity they
    control and mint fresh Google Cloud credentials indefinitely, surviving
    credential rotation. Providers that define an attribute condition, and
    disabled providers, are reported as PASS.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for provider in iam_client.workload_identity_pool_providers:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=provider,
                resource_id=provider.name,
                resource_name=provider.display_name or provider.id,
                location=iam_client.region,
            )
            if provider.disabled or provider.state != "ACTIVE":
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} is not active and cannot vend credentials."
                )
            elif provider.attribute_condition:
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} enforces an attribute condition."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} does not enforce an attribute condition, so "
                    "any external identity from the configured issuer can impersonate "
                    "the federated principals."
                )
            findings.append(report)

        return findings
