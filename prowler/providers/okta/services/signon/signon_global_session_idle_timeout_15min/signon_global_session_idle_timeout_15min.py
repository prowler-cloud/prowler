from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client

DEFAULT_THRESHOLD_MINUTES = 15


class signon_global_session_idle_timeout_15min(Check):
    """STIG V-273186 / OKTA-APP-000020.

    The Default Global Session Policy must contain at least one
    non-default rule whose maximum Okta global session idle time is
    less than or equal to the configured threshold (defaults to 15
    minutes per STIG; override via `okta_max_session_idle_minutes` in
    the audit config).
    """

    def execute(self) -> list[CheckReportOkta]:
        findings = []
        audit_config = signon_client.audit_config or {}
        threshold = audit_config.get(
            "okta_max_session_idle_minutes", DEFAULT_THRESHOLD_MINUTES
        )
        org_url = signon_client.provider.identity.org_url
        for policy in signon_client.global_session_policies.values():
            report = CheckReportOkta(metadata=self.metadata(), resource=policy)
            report.org_url = org_url

            non_default_rules = [r for r in policy.rules if not r.is_default]
            compliant_rules = [
                r
                for r in non_default_rules
                if r.max_session_idle_minutes is not None
                and r.max_session_idle_minutes <= threshold
            ]

            if compliant_rules:
                names = ", ".join(f"'{r.name}'" for r in compliant_rules)
                report.status = "PASS"
                report.status_extended = (
                    f"Global session policy '{policy.name}' has "
                    f"{len(compliant_rules)} rule(s) enforcing idle timeout "
                    f"<= {threshold} minutes: {names}."
                )
            elif not non_default_rules:
                report.status = "FAIL"
                report.status_extended = (
                    f"Global session policy '{policy.name}' has no non-default "
                    f"rules; the catch-all Default Rule cannot enforce a "
                    f"{threshold}-minute idle timeout."
                )
            else:
                names = ", ".join(f"'{r.name}'" for r in non_default_rules)
                report.status = "FAIL"
                report.status_extended = (
                    f"Global session policy '{policy.name}' has non-default "
                    f"rules ({names}) but none enforces idle timeout "
                    f"<= {threshold} minutes."
                )
            findings.append(report)
        return findings
