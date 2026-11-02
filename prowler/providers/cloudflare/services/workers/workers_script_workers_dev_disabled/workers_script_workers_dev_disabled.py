from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)


class workers_script_workers_dev_disabled(Check):
    """Ensure that Workers scripts are not publicly reachable on workers.dev.

    The workers.dev route exposes the Worker on a public `*.workers.dev`
    hostname that sits outside of the account's zones, so zone-level controls
    such as WAF custom rules, rate limiting or Cloudflare Access applied to the
    production hostname can be bypassed.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the workers.dev exposure check.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            workers.dev route is disabled for the script, or FAIL status if it
            is enabled.
        """
        findings = []
        for script in workers_client.scripts:
            # Subdomain status unknown (e.g. no workers.dev subdomain registered).
            if script.workers_dev_enabled is None:
                continue

            report = CheckReportCloudflare(metadata=self.metadata(), resource=script)
            if script.workers_dev_enabled:
                report.status = "FAIL"
                report.status_extended = f"Worker {script.name} is publicly reachable on its workers.dev subdomain."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Worker {script.name} has the workers.dev route disabled."
                )
            findings.append(report)
        return findings
