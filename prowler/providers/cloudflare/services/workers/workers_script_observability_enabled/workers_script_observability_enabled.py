from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)


class workers_script_observability_enabled(Check):
    """Ensure that Workers Logs (observability) are enabled for Workers scripts.

    Workers Logs persist invocation logs, console output and uncaught exceptions,
    which are required to investigate abuse, debug incidents and retain an audit
    trail of what the Worker executed.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Workers observability check.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Workers
            Logs are enabled for the script, or FAIL status otherwise.
        """
        findings = []
        for script in workers_client.scripts:
            # Settings could not be retrieved; the error is logged by the service.
            if script.observability_enabled is None:
                continue

            report = CheckReportCloudflare(metadata=self.metadata(), resource=script)
            if script.observability_enabled and script.observability_logs_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Worker {script.name} has Workers Logs enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Worker {script.name} does not have Workers Logs enabled."
                )
            findings.append(report)
        return findings
