"""Shared evaluation of the system-defined alert rules audited by CIS section 6."""

from typing import TYPE_CHECKING, List, Set

from prowler.lib.check.models import CheckReportGoogleWorkspace

if TYPE_CHECKING:
    from prowler.providers.googleworkspace.services.rules.rules_service import Rules


def evaluate_system_defined_alert(
    client: "Rules",
    metadata: dict,
    rule_name: str,
    expected_severities: Set[str],
) -> List[CheckReportGoogleWorkspace]:
    """Report on one system-defined alert rule against the CIS audit procedure.

    Every recommendation in CIS section 6 asks for the rule to be on, to notify
    by email, to include all super administrators as recipients and to carry a
    specific severity. The severity is evaluated here as well, so a rule that is
    on but classified below what the benchmark asks for cannot pass.

    Args:
        client: the rules client, passed in so each check keeps its own import.
        metadata: the calling check's metadata.
        rule_name: display name of the system-defined alert to evaluate.
        expected_severities: severities the benchmark accepts for this rule.

    Returns:
        One report for the named rule, or an empty list when the policies could
        not be fetched or the rule is not present.
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

        issues = []

        if alert.state != "ACTIVE":
            issues.append("alert is OFF")

        if not alert.email_notifications_enabled:
            issues.append("email notifications are disabled")
        elif not alert.all_super_admins:
            issues.append("email recipients do not include all super administrators")

        if alert.severity not in expected_severities:
            expected = " or ".join(sorted(expected_severities))
            if alert.from_default:
                # The API returned no policy for this rule, so its severity was
                # never observed. Report that instead of blaming the tenant.
                issues.append(
                    f"the rule was not returned by the API, so its severity "
                    f"could not be verified (should be {expected})"
                )
            elif alert.severity is None:
                issues.append(f"severity is not configured (should be {expected})")
            else:
                issues.append(f"severity is {alert.severity} (should be {expected})")

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
