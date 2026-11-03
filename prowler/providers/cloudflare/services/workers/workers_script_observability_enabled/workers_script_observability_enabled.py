from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import (
    workers_client,
)
from prowler.providers.cloudflare.services.workers.workers_manual import (
    workers_manual_reports,
)


class workers_script_observability_enabled(Check):
    """Ensure that Workers Logs persist invocation logs for Workers scripts.

    Workers Logs persist invocation logs, console output and uncaught exceptions,
    which are required to investigate abuse, debug incidents and retain an audit
    trail of what the Worker executed.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the effective Workers Logs configuration of every Worker.

        A Worker passes only when observability and Workers Logs are enabled,
        invocation logs are recorded and the log sampling rate is above zero.

        Returns:
            PASS/FAIL findings per Worker and MANUAL per account whose Workers
            settings could not be retrieved.
        """
        findings = workers_manual_reports(
            self,
            workers_client,
            workers_client.settings_failed_accounts,
            "Workers Logs",
        )
        for script in workers_client.scripts:
            # Settings failed: covered by the account-level MANUAL finding.
            if script.observability_enabled is None:
                continue

            report = CheckReportCloudflare(metadata=self.metadata(), resource=script)
            if not (script.observability_enabled and script.observability_logs_enabled):
                report.status = "FAIL"
                report.status_extended = (
                    f"Worker {script.name} does not have Workers Logs enabled."
                )
            elif not script.invocation_logs_enabled:
                report.status = "FAIL"
                report.status_extended = f"Worker {script.name} has Workers Logs enabled but does not record invocation logs."
            elif not script.log_sampling_rate:
                report.status = "FAIL"
                report.status_extended = f"Worker {script.name} has Workers Logs enabled with a sampling rate of 0, so no logs are kept."
            else:
                report.status = "PASS"
                report.status_extended = f"Worker {script.name} has Workers Logs enabled with invocation logs (sampling rate {script.log_sampling_rate:g})."
            findings.append(report)
        return findings
