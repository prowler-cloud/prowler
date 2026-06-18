from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_cspm_is_on(Check):
    """
    Ensure Microsoft Defender Cloud Security Posture Management (CSPM) is set to On.

    This check evaluates whether the Defender CSPM plan (CloudPosture pricing) is enabled with the Standard tier for each subscription.

    - PASS: The CloudPosture pricing tier is "Standard" (Defender CSPM is on).
    - FAIL: The CloudPosture pricing tier is not "Standard" (Defender CSPM is off).
    """

    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            subscription_name = defender_client.subscriptions.get(
                subscription, subscription
            )
            if "CloudPosture" in pricings:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=pricings["CloudPosture"],
                )
                report.subscription = subscription
                report.resource_name = "Defender plan CSPM"
                report.status = "PASS"
                report.status_extended = f"Defender plan CSPM from subscription {subscription_name} ({subscription}) is set to ON (pricing tier standard)."
                if pricings["CloudPosture"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = f"Defender plan CSPM from subscription {subscription_name} ({subscription}) is set to OFF (pricing tier not standard)."

                findings.append(report)
        return findings
