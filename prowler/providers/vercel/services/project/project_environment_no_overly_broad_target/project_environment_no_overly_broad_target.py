from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client

ALL_ENVIRONMENTS = {"production", "preview", "development"}


class project_environment_no_overly_broad_target(Check):
    """Check that no environment variables target all three environments simultaneously.

    This class verifies that environment variables are not configured to target
    production, preview, and development environments at the same time, which
    violates the principle of least privilege and may expose production secrets
    to development and preview contexts.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the no-overly-broad-target check.

        Iterates over all projects and inspects each environment variable,
        flagging any that target all three environments (production, preview,
        and development) simultaneously.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            broad_keys = []
            for env_var in project.environment_variables:
                targets = {t.lower() for t in env_var.target}
                if ALL_ENVIRONMENTS.issubset(targets):
                    broad_keys.append(env_var.key)

            if broad_keys:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has {len(broad_keys)} environment "
                    f"variable(s) targeting all three environments: "
                    f"{', '.join(broad_keys)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has no environment variables targeting "
                    f"all three environments simultaneously."
                )

            findings.append(report)

        return findings
