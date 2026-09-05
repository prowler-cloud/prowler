from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.lib.service.service import config_value
from prowler.providers.fly.services.machine.machine_client import machine_client

DEFAULT_ALLOWED_PUBLIC_PORTS = [80, 443]


def format_ports(ports: set[int]) -> str:
    """Render a set of ports compactly, collapsing consecutive runs to ranges.

    Args:
        ports: The ports to render.

    Returns:
        str: A sorted, comma-separated list such as ``5432, 8000-8010``.
    """
    ordered = sorted(ports)
    runs = []
    for port in ordered:
        if runs and port == runs[-1][1] + 1:
            runs[-1][1] = port
        else:
            runs.append([port, port])
    return ", ".join(
        str(start) if start == end else f"{start}-{end}" for start, end in runs
    )


class machine_no_public_non_http_ports(Check):
    """Check if a Fly.io machine publishes ports beyond HTTP and HTTPS.

    Machine services with a ``ports`` entry are published on the Fly.io edge.
    Anything other than the HTTP/HTTPS edge ports puts a raw protocol, such as
    PostgreSQL or an S3 API, on the public internet whenever the app holds a
    public IP address. Port ranges (``start_port`` / ``end_port``) are expanded
    so every port of the range is evaluated.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine published port check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []
        allowed_ports = set(
            config_value(
                machine_client.audit_config,
                "allowed_public_ports",
                DEFAULT_ALLOWED_PUBLIC_PORTS,
            )
        )

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)

            published = set()
            for service in machine.services:
                for port in service.ports:
                    published.update(port.published_ports())
            disallowed = published - allowed_ports

            if not disallowed:
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} publishes no "
                    f"edge ports beyond {format_ports(allowed_ports)}."
                    if published
                    else f"Machine {machine.name} in app {machine.app_name} publishes "
                    f"no ports to the Fly.io edge."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} publishes "
                    f"port(s) {format_ports(disallowed)} to the Fly.io edge."
                )

            findings.append(report)

        return findings
