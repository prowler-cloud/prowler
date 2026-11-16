from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_data_protection_policy_configured(Check):
    """Check if CloudWatch Log Groups have a data protection policy configured.

    PASS when the log group has a data protection policy configured.
    FAIL when no data protection policy exists on the log group.
    MANUAL when the policy could not be retrieved (e.g. AccessDenied).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the CloudWatch log group data protection policy check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if logs_client.log_groups is None or (
            not logs_client.log_groups
            and getattr(logs_client, "log_groups_unavailable", False) is True
        ):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "MANUAL"
            report.status_extended = "Log groups could not be retrieved, so data protection policies for CloudWatch log groups could not be verified."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []
            return [report]

        if logs_client.log_groups:
            for log_group in logs_client.log_groups.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
                if "ACCOUNT_DATA_PROTECTION" in log_group.inherited_properties or (
                    log_group.data_protection_policy
                    and log_group.data_protection_status == "ACTIVATED"
                ):
                    report.status = "PASS"
                    report.status_extended = f"Log Group {log_group.name} has a data protection policy configured."
                elif not log_group.data_protection_policy_retrieved:
                    report.status = "MANUAL"
                    report.status_extended = f"Log Group {log_group.name} data protection policy could not be retrieved in region {log_group.region}; verify manually."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Log Group {log_group.name} does not have an active data protection policy configured."
                findings.append(report)

        if (
            logs_client.log_groups
            and getattr(logs_client, "log_groups_unavailable", False) is True
        ):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "MANUAL"
            report.status_extended = "Log groups could not be listed in at least one region; verify data protection policies manually for unlisted groups."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []
            findings.append(report)

        return findings
