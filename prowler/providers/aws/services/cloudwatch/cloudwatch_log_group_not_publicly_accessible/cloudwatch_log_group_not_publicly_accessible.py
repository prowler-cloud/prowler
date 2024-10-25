from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class cloudwatch_log_group_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        public_log_groups = []
        if (
            logs_client.resource_policies is not None
            and logs_client.log_groups is not None
        ):
            for resource_policies in logs_client.resource_policies.values():
                for resource_policy in resource_policies:
                    if is_policy_public(
                        resource_policy.policy, logs_client.audited_account
                    ):
                        for statement in resource_policy.policy.get("Statement", []):
                            public_resources = statement.get("Resource", [])
                            if isinstance(public_resources, str):
                                public_resources = [public_resources]
                            for resource in public_resources:
                                for log_group in logs_client.log_groups.values():
                                    if log_group.arn in resource or resource == "*":
                                        public_log_groups.append(log_group.arn)
            for log_group in logs_client.log_groups.values():
                report = Check_Report_AWS(self.metadata())
                report.region = log_group.region
                report.resource_id = log_group.name
                report.resource_arn = log_group.arn
                report.resource_tags = log_group.tags
                report.status = "PASS"
                report.status_extended = (
                    f"Log Group {log_group.name} is not publicly accessible."
                )
                if log_group.arn in public_log_groups:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Log Group {log_group.name} is publicly accessible."
                    )

                findings.append(report)

        return findings
