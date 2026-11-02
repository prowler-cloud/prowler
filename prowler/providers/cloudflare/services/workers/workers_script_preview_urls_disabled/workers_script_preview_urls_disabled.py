from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)


class workers_script_preview_urls_disabled(Check):
    """Ensure that Preview URLs are disabled for Workers scripts.

    Preview URLs publish every uploaded version of a Worker on a public
    `*.workers.dev` hostname, exposing untested or outdated code paths that are
    not protected by the zone's security controls.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Preview URLs check.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Preview
            URLs are disabled for the script, or FAIL status if they are enabled.
        """
        findings = []
        for script in workers_client.scripts:
            if script.previews_enabled is None:
                continue

            report = CheckReportCloudflare(metadata=self.metadata(), resource=script)
            if script.previews_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Worker {script.name} has Preview URLs enabled."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Worker {script.name} has Preview URLs disabled."
                )
            findings.append(report)
        return findings
