from typing import List
from urllib.parse import parse_qs, urlparse

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.machine.machine_client import machine_client

DEFAULT_SECRET_NAME_PATTERNS = [
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "PASSPHRASE",
]

CREDENTIAL_QUERY_PARAMETERS = [
    "access_token",
    "api_key",
    "apikey",
    "credential",
    "key",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
]


def is_credential_free_url(value: str) -> bool:
    """Return whether a value is an endpoint URL that carries no credential.

    Names such as ``TOKEN_ISSUER_URL`` match the secret-like name patterns while
    holding a plain endpoint, so the value decides: a URL is credential-free when
    it has no userinfo component and no credential-bearing query parameter.

    Args:
        value (str): The environment variable value to classify.

    Returns:
        bool: True when the value is a URL that carries no credential.
    """
    try:
        url = urlparse(value)
    except ValueError:
        return False

    if url.scheme not in ("http", "https") or not url.netloc:
        return False

    if url.username or url.password:
        return False

    parameters = {name.lower() for name in parse_qs(url.query)}
    return parameters.isdisjoint(CREDENTIAL_QUERY_PARAMETERS)


class machine_no_plaintext_secrets_in_env(Check):
    """Check if a Fly.io machine carries secret-like values in its plain config.

    Values placed in the machine's ``env`` block are stored in the machine
    configuration and returned in clear text by the Machines API to anyone who
    can read the app. Secrets belong in Fly secrets, which are encrypted at rest
    and only injected into the running machine.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine secrets handling check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []
        patterns = [
            pattern.upper()
            for pattern in machine_client.audit_config.get(
                "secret_env_name_patterns", DEFAULT_SECRET_NAME_PATTERNS
            )
        ]

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)

            exposed = sorted(
                name
                for name, value in machine.env.items()
                if value
                and any(pattern in name.upper() for pattern in patterns)
                and not is_credential_free_url(value)
            )

            if not exposed:
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} has no "
                    f"secret-like values in its plain machine configuration "
                    f"({len(machine.app_secret_names)} Fly secret(s) injected)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} exposes "
                    f"secret-like values in its plain machine configuration: "
                    f"{', '.join(exposed)}."
                )

            findings.append(report)

        return findings
