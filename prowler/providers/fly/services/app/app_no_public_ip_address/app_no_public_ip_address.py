from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.app.app_client import app_client


class app_no_public_ip_address(Check):
    """Check if a Fly.io app has public IP addresses allocated.

    An app without an allocated public IPv4/IPv6 address is only reachable over
    the organization's private 6PN network, which is the expected posture for
    databases, object storage and other backing services.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io app public IP exposure check.

        Returns:
            List[CheckReportFly]: A report per in-scope app.
        """
        findings = []
        public_apps = app_client.audit_config.get("public_apps", [])

        for app in app_client.apps.values():
            report = CheckReportFly(metadata=self.metadata(), resource=app)

            if not app.public_ips:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} has no public IP address allocated and is only "
                    f"reachable over the private network."
                )
            elif app.name in public_apps:
                addresses = ", ".join(ip.address for ip in app.public_ips)
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} is an approved public app and exposes "
                    f"{addresses}."
                )
            else:
                addresses = ", ".join(
                    f"{ip.address} ({ip.type})" for ip in app.public_ips
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} is reachable from the internet through "
                    f"{addresses}."
                )

            findings.append(report)

        return findings
