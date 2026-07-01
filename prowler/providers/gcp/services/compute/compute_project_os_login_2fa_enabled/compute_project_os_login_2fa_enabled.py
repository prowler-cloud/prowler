from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_project_os_login_2fa_enabled(Check):
    """Ensure that OS Login with 2FA is enabled for a GCP project.

    This check verifies that OS Login Two-Factor Authentication (2FA) is enabled
    at the project level to enforce an additional layer of security for SSH access
    to VM instances.

    - PASS: Project has OS Login 2FA enabled (enable-oslogin-2fa=TRUE).
    - FAIL: Project does not have OS Login 2FA enabled.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for project in compute_client.compute_projects:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=compute_client.projects[project.id],
                project_id=project.id,
                location=compute_client.region,
                resource_name=(
                    compute_client.projects[project.id].name
                    if compute_client.projects[project.id].name
                    else "GCP Project"
                ),
            )
            report.status = "PASS"
            report.status_extended = f"Project {project.id} has OS Login 2FA enabled."
            if not project.enable_oslogin_2fa:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.id} does not have OS Login 2FA enabled."
                )
            findings.append(report)

        return findings
