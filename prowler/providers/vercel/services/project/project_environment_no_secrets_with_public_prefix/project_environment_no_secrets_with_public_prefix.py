from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client
from prowler.providers.vercel.services.project.project_environment_no_secrets_in_plain_type.project_environment_no_secrets_in_plain_type import (
    DEFAULT_SECRET_SUFFIXES,
)

DEFAULT_PUBLIC_ENV_PREFIXES = [
    "NEXT_PUBLIC_",
    "NUXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "VUE_APP_",
    "GATSBY_",
    "EXPO_PUBLIC_",
    "PUBLIC_",
]

# Vercel types whose value is treated as a secret by the platform itself
SENSITIVE_TYPES = ("sensitive", "secret")


class project_environment_no_secrets_with_public_prefix(Check):
    """Check that no secret is exposed through a browser-bundled environment variable.

    Frontend frameworks inline every variable whose name starts with a public
    prefix (``NEXT_PUBLIC_``, ``VITE_``, ``REACT_APP_``...) into the client
    bundle, so its value is readable by anyone who loads the site. This class
    flags variables that carry such a prefix while looking like a secret:
    either their name ends with a secret-like suffix or they are stored with a
    sensitive type. Both lists are configurable through ``public_env_prefixes``
    and ``secret_suffixes`` in audit_config.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the no-secrets-with-public-prefix check.

        Iterates over all projects and inspects each environment variable,
        flagging any variable whose name starts with a public prefix and
        either ends with a secret-like suffix or is stored as sensitive.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        public_prefixes = tuple(
            p.upper()
            for p in project_client.audit_config.get(
                "public_env_prefixes", DEFAULT_PUBLIC_ENV_PREFIXES
            )
        )
        secret_suffixes = tuple(
            s.upper()
            for s in project_client.audit_config.get(
                "secret_suffixes", DEFAULT_SECRET_SUFFIXES
            )
        )

        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            exposed_keys = []
            for env_var in project.environment_variables:
                upper_key = env_var.key.upper()
                if not upper_key.startswith(public_prefixes):
                    continue
                if (
                    upper_key.endswith(secret_suffixes)
                    or env_var.type in SENSITIVE_TYPES
                ):
                    exposed_keys.append(env_var.key)

            if exposed_keys:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has {len(exposed_keys)} secret-like "
                    f"environment variable(s) exposed to the browser through a "
                    f"public prefix: {', '.join(exposed_keys)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has no secret-like environment "
                    f"variables exposed to the browser through a public prefix."
                )

            findings.append(report)

        return findings
