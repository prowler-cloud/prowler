from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_instance_minor_version_upgrade_enabled(Check):
    def execute(self):
        findings = []
        for instance in dms_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "FAIL"
            report.status_extended = f"DMS Replication Instance {instance.id} does not have auto minor version upgrade enabled."
            if instance.auto_minor_version_upgrade:
                report.status = "PASS"
                report.status_extended = f"DMS Replication Instance {instance.id} has auto minor version upgrade enabled."

            findings.append(report)

        return findings
