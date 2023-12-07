from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import autoscaling_client

class autoscaling_group_scaling_enabled(Check):
    def execute(self):
        findings = []

        # Fetch the audit configuration value from prowler config.yaml
        max_autoscaling_group_size = autoscaling_client.audit_config.get(
            "max_autoscaling_group_size", 10
        )
        
        for autoscaling_group in autoscaling_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = autoscaling_group.region
            report.resource_id = autoscaling_group.name
            report.resource_arn = autoscaling_group.arn
            report.resource_tags = autoscaling_group.tags

            report.status = "PASS"
            report.status_extended = f"Auto Scaling group {autoscaling_group.name} has scaling enabled."

            # Check if scaling is enabled
            if not autoscaling_group.scaling_enabled:
                report.status = "FAIL"
                report.status_extended = f"Auto Scaling group {autoscaling_group.name} does not have scaling enabled."

            findings.append(report)

        return findings
