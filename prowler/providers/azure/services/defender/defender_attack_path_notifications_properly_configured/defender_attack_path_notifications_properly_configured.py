from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_attack_path_notifications_properly_configured(Check):
    """
    Ensure that email notifications for attack paths are enabled.

    This check evaluates whether Microsoft Defender for Cloud is configured to send email notifications for attack paths in each Azure subscription.
    - PASS: Notifications are enabled for attack paths with a risk level set (not None) and equal or higher than the configured minimum.
    - FAIL: Notifications are not enabled for attack paths in the subscription or the risk level is too low.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        # Get the minimal risk level from config, default to 'High'
        risk_levels = ["Low", "Medium", "High", "Critical"]
        min_risk_level = defender_client.audit_config.get(
            "defender_attack_path_minimal_risk_level", "High"
        )
        if min_risk_level not in risk_levels:
            min_risk_level = "High"
        min_risk_index = risk_levels.index(min_risk_level)

        for (
            subscription_name,
            security_contact_configurations,
        ) in defender_client.security_contact_configurations.items():
            for contact_configuration in security_contact_configurations.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=contact_configuration
                )
                report.resource_name = (
                    contact_configuration.name
                    if contact_configuration.name
                    else "Security Contact"
                )
                report.subscription = subscription_name
                actual_risk_level = getattr(
                    contact_configuration, "attack_path_minimal_risk_level", None
                )
                if not actual_risk_level or actual_risk_level not in risk_levels:
                    report.status = "FAIL"
                    report.status_extended = f"Attack path notifications are not enabled in subscription {subscription_name} for security contact {contact_configuration.name}."
                else:
                    actual_risk_index = risk_levels.index(actual_risk_level)
                    if actual_risk_index <= min_risk_index:
                        report.status = "PASS"
                        report.status_extended = f"Attack path notifications are enabled with minimal risk level {actual_risk_level} in subscription {subscription_name} for security contact {contact_configuration.name}."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Attack path notifications are enabled with minimal risk level {actual_risk_level} in subscription {subscription_name} for security contact {contact_configuration.name}."
                findings.append(report)

        return findings
