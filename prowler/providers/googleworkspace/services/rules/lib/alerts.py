"""Shared evaluation of the system-defined alert rules audited by CIS section 6."""

from typing import TYPE_CHECKING, List

from prowler.lib.check.models import CheckReportGoogleWorkspace

if TYPE_CHECKING:
    from prowler.providers.googleworkspace.services.rules.rules_service import Rules

# A rule classified above what the benchmark asks for is stricter, not weaker,
# so severities are compared by rank instead of by equality.
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# The rule can be active while its delivery to the alert center is switched
# off, which is what the audit's "Ensure that Alerts is set to On" checks.
ALERT_CENTER_DISABLED = "DISABLED"


def _severity_issue(severity: str, minimum_severity: str) -> str:
    """Return why a severity does not meet the benchmark, or an empty string."""
    if severity is None:
        return f"severity is not configured (should be at least {minimum_severity})"
    rank = SEVERITY_RANK.get(severity)
    if rank is None:
        return (
            f"severity is {severity}, which is not one of "
            f"{', '.join(SEVERITY_RANK)}, so it could not be compared against "
            f"the {minimum_severity} the benchmark asks for"
        )
    if rank < SEVERITY_RANK[minimum_severity]:
        return f"severity is {severity} (should be at least {minimum_severity})"
    return ""


def evaluate_system_defined_alert(
    client: "Rules",
    metadata: dict,
    rule_name: str,
    minimum_severity: str,
) -> List[CheckReportGoogleWorkspace]:
    """Report on one system-defined alert rule against the CIS audit procedure.

    Every recommendation in CIS section 6 asks for the rule to be on, to notify
    by email, to include all super administrators as recipients and to carry a
    minimum severity. Returns no finding at all when the policies could not be
    fetched or the rule is not among the ones the client collected.
    """
    findings = []

    if not client.policies_fetched:
        return findings

    for alert in client.system_defined_alerts:
        if alert.display_name != rule_name:
            continue

        domain = client.provider.identity.domain
        report = CheckReportGoogleWorkspace(
            metadata=metadata,
            resource=alert,
            resource_id=f"systemDefinedAlert/{rule_name}",
            resource_name=rule_name,
            customer_id=client.provider.identity.customer_id,
        )

        if alert.from_default:
            # Nothing was observed: the state below is Google's documented
            # default and the severity has no documented default at all.
            if alert.state != "ACTIVE":
                report.status = "FAIL"
                report.status_extended = (
                    f"System-defined alert rule '{rule_name}' was not returned "
                    f"by the API in domain {domain} and Google's default for it "
                    f"is OFF."
                )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    f"System-defined alert rule '{rule_name}' was not returned "
                    f"by the API in domain {domain}, so its configuration could "
                    f"not be verified. Review it in the Admin console: it should "
                    f"be ON, notify all super administrators by email and be set "
                    f"to {minimum_severity} severity or higher."
                )
            findings.append(report)
            continue

        issues = []

        if alert.state != "ACTIVE":
            issues.append("alert is OFF")

        # Only an explicit DISABLED fails. The API does not return this field
        # even for a rule that is ON and has a severity set, and a severity
        # cannot be configured for the alert center while delivery is off, so
        # treating its absence as unverified would leave every one of these
        # checks permanently MANUAL.
        if alert.alert_center_status == ALERT_CENTER_DISABLED:
            issues.append("the alert is not sent to the alert center")

        if not alert.email_notifications_enabled:
            issues.append("email notifications are disabled")
        elif not alert.all_super_admins:
            issues.append("email recipients do not include all super administrators")

        severity = _severity_issue(alert.severity, minimum_severity)
        if severity:
            issues.append(severity)

        if issues:
            report.status = "FAIL"
            report.status_extended = (
                f"System-defined alert rule '{rule_name}' is not properly "
                f"configured in domain {domain}: {', '.join(issues)}."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"System-defined alert rule '{rule_name}' is properly "
                f"configured in domain {domain}: alert is ON, email "
                f"notifications are enabled, recipients include all super "
                f"administrators and severity is {alert.severity}."
            )

        findings.append(report)

    return findings
