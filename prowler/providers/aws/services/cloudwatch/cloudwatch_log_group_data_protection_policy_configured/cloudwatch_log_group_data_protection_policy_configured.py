from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client

# Operations that make a data protection policy statement actively protect sensitive data.
PROTECTIVE_OPERATIONS = {"Audit", "Deidentify"}


def _has_active_data_protection(policy: dict) -> bool:
    """Return True when the policy has at least one statement that audits or de-identifies
    one or more sensitive-data identifiers."""
    if not isinstance(policy, dict):
        return False
    for statement in policy.get("Statement", []):
        if not isinstance(statement, dict):
            continue
        data_identifiers = statement.get("DataIdentifier", [])
        operation = statement.get("Operation", {})
        if data_identifiers and any(
            op in operation for op in PROTECTIVE_OPERATIONS
        ):
            return True
    return False


class cloudwatch_log_group_data_protection_policy_configured(Check):
    def execute(self):
        findings = []
        if logs_client.log_groups:
            for log_group in logs_client.log_groups.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
                if _has_active_data_protection(log_group.data_protection_policy):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Log Group {log_group.name} has a data protection policy that "
                        "audits or de-identifies sensitive data identifiers."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Log Group {log_group.name} does not have a data protection policy "
                        "configured to audit or de-identify sensitive data identifiers."
                    )
                findings.append(report)
        return findings
