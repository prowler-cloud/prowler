from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.workspaces.workspaces_client import (
    workspaces_client,
)


class workspaces_volume_encryption_enabled(Check):
    def execute(self):
        findings = []
        for workspace in workspaces_client.workspaces:
            report = Check_Report_AWS(self.metadata())
            report.region = workspace.region
            report.resource_id = workspace.id
            report.resource_arn = workspace.arn
            report.status = "PASS"
            report.status_extended = f"WorkSpaces workspace {workspace.id} without root or user unencrypted volumes"
            if not workspace.user_volume_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"WorkSpaces workspace {workspace.id} with user unencrypted volumes"
                )
            if not workspace.root_volume_encryption_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"WorkSpaces workspace {workspace.id} with root unencrypted volumes"
                )
            if (
                not workspace.root_volume_encryption_enabled
                and not workspace.user_volume_encryption_enabled
            ):
                report.status = "FAIL"
                report.status_extended = f"WorkSpaces workspace {workspace.id} with root and user unencrypted volumes"

            findings.append(report)
        return findings
