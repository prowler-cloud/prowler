from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client

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
        if data_identifiers and any(op in operation for op in PROTECTIVE_OPERATIONS):
            return True
    return False


class cloudwatch_log_group_data_protection_policy_configured(Check):
    """Check if CloudWatch Log Groups have a data protection policy configured.

    PASS when the log group has an active data protection policy configured or inherited.
    FAIL when no active data protection policy exists on the log group.
    MANUAL when the policy could not be retrieved (e.g. AccessDenied).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the CloudWatch log group data protection policy check.

        Returns:
            A list of reports containing the result of the check.
        """
        if logs_client.log_groups is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "MANUAL"
            report.status_extended = "Log groups could not be retrieved, so data protection policies for CloudWatch log groups could not be verified."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []
            return [report]

        findings = []
        for log_group in logs_client.log_groups.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)

            if "ACCOUNT_DATA_PROTECTION" in log_group.inherited_properties:
                report.status = "PASS"
                report.status_extended = f"Log Group {log_group.name} has a data protection policy configured via account-level inheritance."
            elif (
                log_group.data_protection_policy
                and log_group.data_protection_status == "ACTIVATED"
                and _has_active_data_protection(log_group.data_protection_policy)
            ):
                report.status = "PASS"
                report.status_extended = f"Log Group {log_group.name} has a data protection policy configured to audit or de-identify sensitive data identifiers."
            elif not log_group.data_protection_policy_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Log Group {log_group.name} data protection policy could not be retrieved in region {log_group.region}; verify manually."
            else:
                report.status = "FAIL"
                report.status_extended = f"Log Group {log_group.name} does not have an active data protection policy configured."
            findings.append(report)
        return findings
