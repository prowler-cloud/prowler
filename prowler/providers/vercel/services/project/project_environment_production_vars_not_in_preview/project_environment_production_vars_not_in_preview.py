from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client

SENSITIVE_TYPES = {"secret", "encrypted"}


class project_environment_production_vars_not_in_preview(Check):
    """Check that sensitive production environment variables do not also target preview.

    This class verifies that environment variables using "secret" or "encrypted"
    types that target "production" do not simultaneously target "preview"
    deployments, which could expose production credentials to untrusted code
    running in preview builds from pull requests.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the production-vars-not-in-preview check.

        Iterates over all projects, inspects each environment variable with a
        sensitive type (secret or encrypted), and flags any that target both
        "production" and "preview" environments.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            leaking_keys = []
            for env_var in project.environment_variables:
                if env_var.type in SENSITIVE_TYPES:
                    targets = {t.lower() for t in env_var.target}
                    if "production" in targets and "preview" in targets:
                        leaking_keys.append(env_var.key)

            if leaking_keys:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has {len(leaking_keys)} sensitive "
                    f"production environment variable(s) also targeting preview: "
                    f"{', '.join(leaking_keys)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has no sensitive production environment "
                    f"variables leaking to preview deployments."
                )

            findings.append(report)

        return findings
