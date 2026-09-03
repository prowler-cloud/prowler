from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.app.app_client import app_client
from prowler.providers.fly.services.app.app_service import SHARED_NETWORK


class app_uses_dedicated_private_network(Check):
    """Check if a Fly.io app runs on a dedicated private network.

    Apps left on the organization's shared network can reach every other app in
    the organization over 6PN. A per-app (per-tenant) network keeps that lateral
    reachability inside a single tenant.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io private networking check.

        Returns:
            List[CheckReportFly]: A report per in-scope app.
        """
        findings = []

        for app in app_client.apps.values():
            report = CheckReportFly(metadata=self.metadata(), resource=app)

            if not app.network or not app.network.strip():
                # The Machines API did not return the network: unknown, not shared.
                report.status = "MANUAL"
                report.status_extended = (
                    f"App {app.name} network assignment could not be determined "
                    f"because the Fly.io API did not return its network; verify it "
                    f"manually with 'fly apps list' or the Machines API."
                )
            elif app.network == SHARED_NETWORK:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} runs on the shared organization network "
                    f"'{SHARED_NETWORK}' and can reach every other app on it over 6PN."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} runs on the dedicated private network "
                    f"{app.network}."
                )

            findings.append(report)

        return findings
