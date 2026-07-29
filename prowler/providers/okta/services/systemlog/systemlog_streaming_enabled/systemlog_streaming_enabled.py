from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.systemlog.lib.systemlog_helpers import (
    missing_log_streams_scope_finding,
)
from prowler.providers.okta.services.systemlog.systemlog_client import systemlog_client
from prowler.providers.okta.services.systemlog.systemlog_service import LogStream


class systemlog_streaming_enabled(Check):
    """Verifies that at least one Okta Log Stream is configured and active.

    Off-loading audit records to a central SIEM (AWS EventBridge, Splunk
    Cloud, etc.) is the standard mechanism for centralised retention.
    An alternative path — pulling the System Log API into an external
    SIEM — is allowed by the requirement, but cannot be verified
    automatically; this check emits a MANUAL note in that case.
    """

    def execute(self) -> list[CheckReportOkta]:
        findings: list[CheckReportOkta] = []
        org_domain = systemlog_client.provider.identity.org_domain

        missing_scope = systemlog_client.missing_scope.get("log_streams")
        if missing_scope:
            findings.append(
                missing_log_streams_scope_finding(
                    self.metadata(), org_domain, missing_scope
                )
            )
            return findings

        active_streams = [
            stream
            for stream in systemlog_client.log_streams.values()
            if not stream.status or stream.status.upper() == "ACTIVE"
        ]

        if not systemlog_client.log_streams:
            placeholder = LogStream(
                id="okta-log-streams-missing",
                name="(no Log Streams configured)",
                status="MISSING",
                type="",
            )
            report = CheckReportOkta(
                metadata=self.metadata(), resource=placeholder, org_domain=org_domain
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Okta Log Streams are configured. Configure a Log Stream "
                "(Reports > Log Streaming) to off-load audit records to a "
                "central SIEM. If an external SIEM is already pulling logs "
                "via the System Log API, mutelist this check with that "
                "evidence."
            )
            findings.append(report)
            return findings

        if not active_streams:
            placeholder = LogStream(
                id="okta-log-streams-inactive",
                name="(no active Log Streams)",
                status="INACTIVE",
                type="",
            )
            report = CheckReportOkta(
                metadata=self.metadata(), resource=placeholder, org_domain=org_domain
            )
            report.status = "FAIL"
            report.status_extended = (
                f"{len(systemlog_client.log_streams)} Okta Log Stream(s) are "
                "configured but none are ACTIVE. Activate a Log Stream to "
                "off-load audit records to a central SIEM."
            )
            findings.append(report)
            return findings

        for stream in active_streams:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=stream, org_domain=org_domain
            )
            report.status = "PASS"
            report.status_extended = (
                f"Okta Log Stream '{stream.name}' (type={stream.type or 'unset'}) "
                "is ACTIVE and off-loads audit records to a central SIEM."
            )
            findings.append(report)
        return findings
