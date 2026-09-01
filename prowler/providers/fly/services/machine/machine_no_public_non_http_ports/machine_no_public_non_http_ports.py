from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.machine.machine_client import machine_client

DEFAULT_ALLOWED_PUBLIC_PORTS = [80, 443]


class machine_no_public_non_http_ports(Check):
    """Check if a Fly.io machine publishes ports beyond HTTP and HTTPS.

    Machine services with a ``ports`` entry are published on the Fly.io edge.
    Anything other than the HTTP/HTTPS edge ports puts a raw protocol, such as
    PostgreSQL or an S3 API, on the public internet whenever the app holds a
    public IP address.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine published port check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []
        allowed_ports = machine_client.audit_config.get(
            "allowed_public_ports", DEFAULT_ALLOWED_PUBLIC_PORTS
        )

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)

            published = [
                port.port
                for service in machine.services
                for port in service.ports
                if port.port is not None
            ]
            disallowed = sorted(
                {port for port in published if port not in allowed_ports}
            )

            if not disallowed:
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} publishes no "
                    f"edge ports beyond {', '.join(str(port) for port in allowed_ports)}."
                    if published
                    else f"Machine {machine.name} in app {machine.app_name} publishes "
                    f"no ports to the Fly.io edge."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} publishes "
                    f"port(s) {', '.join(str(port) for port in disallowed)} to the "
                    f"Fly.io edge."
                )

            findings.append(report)

        return findings
