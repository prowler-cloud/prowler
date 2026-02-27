from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client

SECRET_SUFFIXES = (
    "_KEY",
    "_SECRET",
    "_TOKEN",
    "_PASSWORD",
    "_API_KEY",
    "_PRIVATE_KEY",
)


class environment_no_secrets_in_plain_type(Check):
    """Check that no environment variables with secret-like name suffixes are stored as plain text.

    This class verifies that environment variables whose names end with common
    secret suffixes (_KEY, _SECRET, _TOKEN, _PASSWORD, _API_KEY, _PRIVATE_KEY)
    are not stored with the "plain" type, which makes their values readable in
    the dashboard and API responses.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the no-secrets-in-plain-type check.

        Iterates over all projects and inspects each environment variable,
        flagging any variable whose name ends with a known secret suffix and
        is stored as "plain" type.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            plain_secret_keys = []
            for env_var in project.environment_variables:
                upper_key = env_var.key.upper()
                if any(upper_key.endswith(suffix) for suffix in SECRET_SUFFIXES):
                    if env_var.type == "plain":
                        plain_secret_keys.append(env_var.key)

            if plain_secret_keys:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has {len(plain_secret_keys)} secret-like "
                    f"environment variable(s) stored as plain text: "
                    f"{', '.join(plain_secret_keys)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has no secret-like environment variables "
                    f"stored as plain text."
                )

            findings.append(report)

        return findings
