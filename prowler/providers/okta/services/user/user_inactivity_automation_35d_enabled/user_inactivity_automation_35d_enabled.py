from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.user.lib.user_helpers import (
    missing_user_scope_finding,
)
from prowler.providers.okta.services.user.user_client import user_client
from prowler.providers.okta.services.user.user_service import UserAutomation

DEFAULT_INACTIVITY_DAYS = 35
SUSPENSION_LIFECYCLE_ACTIONS = {"SUSPENDED", "DEACTIVATED", "DEPROVISIONED"}


class user_inactivity_automation_35d_enabled(Check):
    """Verifies that Okta suspends/deactivates users after 35 days of inactivity.

    A Workflows Automation must exist with:
    - status ACTIVE,
    - schedule active,
    - condition `User Inactivity in Okta = 35 days`,
    - action that changes the user state to Suspended / Deactivated,
    - applied to a group covering every user (typically `Everyone`).

    When user sourcing is delegated to an external directory (Active
    Directory or LDAP), the requirement is N/A on the Okta side — the
    connected directory is expected to enforce inactivity-based
    deactivation instead. Threshold override:
    `okta_user_inactivity_max_days` in the audit config.
    """

    def execute(self) -> list[CheckReportOkta]:
        findings: list[CheckReportOkta] = []
        audit_config = user_client.audit_config or {}
        threshold_days = audit_config.get(
            "okta_user_inactivity_max_days", DEFAULT_INACTIVITY_DAYS
        )
        org_domain = user_client.provider.identity.org_domain

        for scope_key in ("automations", "identity_providers"):
            missing_scope = user_client.missing_scope.get(scope_key)
            if missing_scope:
                findings.append(
                    missing_user_scope_finding(
                        self.metadata(), org_domain, missing_scope
                    )
                )
                return findings

        # External-directory N/A path.
        if user_client.external_directory_idps:
            idp_names = ", ".join(
                f"'{idp.name}' (type={idp.type})"
                for idp in user_client.external_directory_idps.values()
            )
            placeholder = UserAutomation(
                id="okta-user-inactivity-na-external-directory",
                name="(external directory enforces inactivity)",
                status="N/A",
            )
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=placeholder,
                org_domain=org_domain,
            )
            report.status = "MANUAL"
            report.status_extended = (
                "User sourcing is delegated to an external directory "
                f"({idp_names}). The 35-day inactivity disable requirement is "
                "expected to be enforced by the connected directory rather "
                "than by an Okta automation. Confirm out-of-band that the "
                "external directory disables accounts after "
                f"{threshold_days} days of inactivity."
            )
            findings.append(report)
            return findings

        compliant_automations = [
            automation
            for automation in user_client.automations.values()
            if _is_compliant(automation, threshold_days)
        ]

        if not user_client.automations:
            placeholder = UserAutomation(
                id="okta-user-inactivity-no-automations",
                name="(no automations configured)",
                status="MISSING",
            )
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=placeholder,
                org_domain=org_domain,
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Okta Workflows automations are configured. Create an "
                "automation that suspends or deactivates users after "
                f"{threshold_days} days of inactivity, scoped to a group "
                "covering every user (typically 'Everyone'), with an active "
                "schedule."
            )
            findings.append(report)
            return findings

        if compliant_automations:
            for automation in compliant_automations:
                report = CheckReportOkta(
                    metadata=self.metadata(),
                    resource=automation,
                    org_domain=org_domain,
                )
                report.status = "PASS"
                groups_label = ", ".join(automation.applies_to_groups)
                report.status_extended = (
                    f"Okta automation '{automation.name}' is ACTIVE with an "
                    f"active schedule, triggers after "
                    f"{automation.inactivity_days} days of inactivity, and "
                    f"changes the user state to "
                    f"{automation.lifecycle_action or 'unset'}. "
                    f"Applied to group(s): {groups_label}. Verify that these "
                    "group(s) cover every user. Okta has no built-in "
                    "'Everyone' group ID, so tenant-wide coverage cannot be "
                    "asserted automatically."
                )
                findings.append(report)
            return findings

        # Automations exist but none satisfy the predicate — surface the
        # closest candidate for the auditor.
        candidate = _closest_candidate(user_client.automations.values())
        report = CheckReportOkta(
            metadata=self.metadata(),
            resource=candidate
            or UserAutomation(
                id="okta-user-inactivity-noncompliant",
                name="(no compliant automation)",
                status="MISSING",
            ),
            org_domain=org_domain,
        )
        report.status = "FAIL"
        report.status_extended = _failure_message(candidate, threshold_days)
        findings.append(report)
        return findings


def _is_compliant(automation: UserAutomation, threshold_days: int) -> bool:
    # `applies_to_groups` must be non-empty — Okta USER_LIFECYCLE policies
    # do not implicitly cover every user; the scope is whatever group IDs
    # the operator put in `people.groups.include`. An empty scope means
    # the automation runs against nobody. Operator must still verify those
    # group(s) cover the intended user population (surfaced in the PASS
    # status_extended).
    return bool(
        automation.status.upper() == "ACTIVE"
        and automation.schedule_status.upper() == "ACTIVE"
        and automation.inactivity_days is not None
        and automation.inactivity_days <= threshold_days
        and (automation.lifecycle_action or "").upper() in SUSPENSION_LIFECYCLE_ACTIONS
        and bool(automation.applies_to_groups)
    )


def _closest_candidate(automations):
    automations = list(automations)
    if not automations:
        return None
    automations.sort(
        key=lambda a: (
            0 if a.status.upper() == "ACTIVE" else 1,
            0 if a.schedule_status.upper() == "ACTIVE" else 1,
            (
                abs(a.inactivity_days - DEFAULT_INACTIVITY_DAYS)
                if a.inactivity_days is not None
                else 10_000
            ),
            a.name,
        )
    )
    return automations[0]


def _failure_message(automation, threshold_days):
    if automation is None:
        return f"No Okta automation enforces {threshold_days}-day inactivity disable."
    issues = []
    if automation.status.upper() != "ACTIVE":
        issues.append(f"status {automation.status or 'unset'}")
    if automation.schedule_status.upper() != "ACTIVE":
        issues.append(f"schedule {automation.schedule_status or 'unset'}")
    if automation.inactivity_days is None:
        issues.append("no inactivity condition")
    elif automation.inactivity_days > threshold_days:
        issues.append(
            f"inactivity {automation.inactivity_days}d (max {threshold_days}d)"
        )
    action = (automation.lifecycle_action or "").upper()
    if action not in SUSPENSION_LIFECYCLE_ACTIONS:
        issues.append(f"action {automation.lifecycle_action or 'unset'}")
    if not automation.applies_to_groups:
        issues.append("no group scope")
    detail = ", ".join(issues) if issues else "incomplete"
    return (
        f"Okta automation '{automation.name}' fails {threshold_days}d "
        f"inactivity: {detail}."
    )
