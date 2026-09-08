from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.accessapproval_client import (
    accessapproval_client,
)


class iam_account_access_approval_enabled(Check):
    """Ensure Access Approval is enabled for every audited project.

    - PASS: The project has Access Approval settings configured.
    - FAIL: Access Approval is not configured (404 on the settings read), or
      the accessapproval.googleapis.com API is disabled — with the API off,
      Access Approval provably cannot be enabled.
    - MANUAL: The settings could not be read (permission error) or the API
      activation state could not be determined.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Evaluate Access Approval for the audited projects.

        Returns:
            list[Check_Report_GCP]: One report per audited project.
        """
        findings = []
        for project_id in accessapproval_client.project_ids:
            # Under --skip-api-check a disabled API is detected while reading
            # the settings; those projects are reported by the loop below.
            if project_id in accessapproval_client.api_disabled_project_ids:
                continue
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=accessapproval_client.projects[project_id],
                project_id=project_id,
                location=accessapproval_client.region,
            )
            report.status = "PASS"
            report.status_extended = (
                f"Project {project_id} has Access Approval enabled."
            )
            if project_id in accessapproval_client.settings_lookup_failed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate Access Approval for project {project_id}: "
                    "the Access Approval settings could not be read. Verify that "
                    "the Access Approval API is enabled and the scanning "
                    "credentials have the accessapproval.settings.get permission."
                )
            elif project_id not in accessapproval_client.settings:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project_id} does not have Access Approval enabled."
                )
            findings.append(report)

        # Projects filtered out by the API-activation precheck never reach
        # _get_settings(): report them instead of silently skipping. A
        # definitively disabled API means Access Approval cannot be enabled
        # (FAIL); an undetermined state is an evidence gap (MANUAL).
        for project_id in sorted(accessapproval_client.api_disabled_project_ids):
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=accessapproval_client.projects[project_id],
                project_id=project_id,
                location=accessapproval_client.region,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Project {project_id} does not have Access Approval enabled: "
                "the accessapproval.googleapis.com API is disabled."
            )
            findings.append(report)

        for project_id in sorted(accessapproval_client.api_state_unknown_project_ids):
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=accessapproval_client.projects[project_id],
                project_id=project_id,
                location=accessapproval_client.region,
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate Access Approval for project {project_id}: "
                "the activation state of the accessapproval.googleapis.com API "
                "could not be determined. Verify that the scanning credentials "
                "can call serviceusage.services.get for the project."
            )
            findings.append(report)

        return findings
