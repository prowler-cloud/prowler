from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)
from prowler.providers.cloudflare.services.workers.workers_manual import (
    workers_manual_reports,
)


class workers_script_preview_urls_disabled(Check):
    """Ensure that Preview URLs are disabled for Workers scripts.

    Preview URLs publish every uploaded version of a Worker on a public
    `*.workers.dev` hostname, exposing untested or outdated code paths that are
    not protected by the zone's security controls.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate whether Preview URLs are enabled for every Worker.

        Returns:
            PASS when Preview URLs are disabled, FAIL when they are enabled, and
            MANUAL per account whose Workers data could not be retrieved.
        """
        findings = workers_manual_reports(
            self,
            workers_client,
            workers_client.subdomain_failed_accounts,
            "Preview URLs",
        )
        for script in workers_client.scripts:
            # Lookup failed: covered by the account-level MANUAL finding.
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
