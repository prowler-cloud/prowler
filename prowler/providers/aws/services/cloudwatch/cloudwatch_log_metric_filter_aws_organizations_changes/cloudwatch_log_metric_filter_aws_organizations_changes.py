from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    check_cloudwatch_log_metric_filter,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_metric_filter_aws_organizations_changes(Check):
    def execute(self):
        pattern = r"\$\.eventSource\s*=\s*.?organizations\.amazonaws\.com.+\$\.eventName\s*=\s*.?AcceptHandshake.+\$\.eventName\s*=\s*.?AttachPolicy.+\$\.eventName\s*=\s*.?CancelHandshake.+\$\.eventName\s*=\s*.?CreateAccount.+\$\.eventName\s*=\s*.?CreateOrganization.+\$\.eventName\s*=\s*.?CreateOrganizationalUnit.+\$\.eventName\s*=\s*.?CreatePolicy.+\$\.eventName\s*=\s*.?DeclineHandshake.+\$\.eventName\s*=\s*.?DeleteOrganization.+\$\.eventName\s*=\s*.?DeleteOrganizationalUnit.+\$\.eventName\s*=\s*.?DeletePolicy.+\$\.eventName\s*=\s*.?EnableAllFeatures.+\$\.eventName\s*=\s*.?EnablePolicyType.+\$\.eventName\s*=\s*.?InviteAccountToOrganization.+\$\.eventName\s*=\s*.?LeaveOrganization.+\$\.eventName\s*=\s*.?DetachPolicy.+\$\.eventName\s*=\s*.?DisablePolicyType.+\$\.eventName\s*=\s*.?MoveAccount.+\$\.eventName\s*=\s*.?RemoveAccountFromOrganization.+\$\.eventName\s*=\s*.?UpdateOrganizationalUnit.+\$\.eventName\s*=\s*.?UpdatePolicy.?"
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No CloudWatch log groups found with metric filters or alarms associated."
        )
        report.region = cloudwatch_client.region
        report.resource_id = logs_client.audited_account
        report.resource_arn = f"arn:{logs_client.audited_partition}:logs:{logs_client.region}:{logs_client.audited_account}:log-group"
        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            report,
        )

        findings.append(report)
        return findings
