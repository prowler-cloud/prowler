import re
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client

SENSITIVE_PATTERNS = [
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "CREDENTIAL",
    "API_KEY",
    "PRIVATE",
    "AUTH",
]

# Pre-compiled regex: each pattern must appear as a whole word (bounded by _ or string edges)
_SENSITIVE_RE = re.compile(r"(?:^|_)(?:" + "|".join(SENSITIVE_PATTERNS) + r")(?:_|$)")


class project_environment_sensitive_vars_encrypted(Check):
    """Check if environment variables with sensitive-looking names use encrypted or secret types.

    This class verifies that any environment variable whose name contains common
    secret-related keywords (KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL, API_KEY,
    PRIVATE, AUTH) is stored with type "encrypted" or "secret", not "plain".
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the sensitive environment variable encryption check.

        Iterates over all projects, inspects each environment variable, and
        flags any variable whose name matches a sensitive pattern but is stored
        as a plain-text type.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            plain_sensitive_keys = []
            for env_var in project.environment_variables:
                upper_key = env_var.key.upper()
                if _SENSITIVE_RE.search(upper_key):
                    if env_var.type not in ("encrypted", "secret"):
                        plain_sensitive_keys.append(env_var.key)

            if plain_sensitive_keys:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has {len(plain_sensitive_keys)} sensitive "
                    f"environment variable(s) stored as plain text: "
                    f"{', '.join(plain_sensitive_keys)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has all sensitive environment variables "
                    f"properly encrypted or uses no sensitive variables."
                )

            findings.append(report)

        return findings
