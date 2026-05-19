from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy

DEFAULT_THRESHOLD_MINUTES = 18 * 60


class signon_global_session_lifetime_18h(Check):
    """STIG V-273203 / OKTA-APP-001665.

    The DISA STIG requires the Okta Default Policy to have an active
    Priority 1 rule that is not the built-in Default Rule, and that
    rule must set the maximum Okta global session lifetime to the
    configured threshold or lower (defaults to 18 hours per STIG;
    override via `okta_max_session_lifetime_minutes` in the audit config).
    """

    def execute(self) -> list[CheckReportOkta]:
        audit_config = signon_client.audit_config or {}
        threshold = audit_config.get(
            "okta_max_session_lifetime_minutes", DEFAULT_THRESHOLD_MINUTES
        )
        org_domain = signon_client.provider.identity.org_domain
        policy = self._get_default_policy()
        report = CheckReportOkta(
            metadata=self.metadata(), resource=policy, org_domain=org_domain
        )

        if policy.id == "default-policy-missing":
            report.status = "FAIL"
            report.status_extended = (
                "Default Global Session Policy was not found. STIG V-273203 "
                "requires the Default Policy to contain an active Priority 1 "
                f"non-default rule with session lifetime <= {threshold} minutes."
            )
            return [report]

        if policy.status and policy.status.upper() != "ACTIVE":
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' is in "
                f"status '{policy.status}'. STIG V-273203 requires an active "
                "Default Policy with an active Priority 1 non-default rule."
            )
            return [report]

        active_rules = sorted(
            [
                rule
                for rule in policy.rules
                if not rule.status or rule.status.upper() == "ACTIVE"
            ],
            key=lambda rule: (
                rule.priority if rule.priority is not None else float("inf"),
                rule.name,
            ),
        )
        if not active_rules:
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' has no active "
                "rules. STIG V-273203 requires an active Priority 1 non-default "
                f"rule with session lifetime <= {threshold} minutes."
            )
            return [report]

        priority_one_rule = active_rules[0]
        if priority_one_rule.priority != 1:
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' has no active "
                f"Priority 1 rule. The first active rule is '{priority_one_rule.name}' "
                f"at priority {priority_one_rule.priority}."
            )
            return [report]

        if priority_one_rule.is_default or priority_one_rule.name == "Default Rule":
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' uses "
                f"'{priority_one_rule.name}' as its active Priority 1 rule. "
                "The STIG requires a non-default Priority 1 rule."
            )
            return [report]

        lifetime = priority_one_rule.max_session_lifetime_minutes
        if lifetime is None:
            report.status = "FAIL"
            report.status_extended = (
                f"Priority 1 non-default rule '{priority_one_rule.name}' in "
                f"Default Global Session Policy '{policy.name}' does not define "
                "a maximum Okta global session lifetime."
            )
            return [report]

        if lifetime == 0:
            report.status = "FAIL"
            report.status_extended = (
                f"Priority 1 non-default rule '{priority_one_rule.name}' in "
                f"Default Global Session Policy '{policy.name}' disables the "
                "maximum Okta global session lifetime by setting it to 0 minutes."
            )
            return [report]

        if lifetime <= threshold:
            report.status = "PASS"
            report.status_extended = (
                f"Priority 1 non-default rule '{priority_one_rule.name}' in "
                f"Default Global Session Policy '{policy.name}' sets the "
                f"maximum Okta global session lifetime to {lifetime} minutes, "
                f"meeting the configured threshold of {threshold} minutes."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Priority 1 non-default rule '{priority_one_rule.name}' in "
                f"Default Global Session Policy '{policy.name}' sets the "
                f"maximum Okta global session lifetime to {lifetime} minutes, "
                f"exceeding the configured threshold of {threshold} minutes."
            )
        return [report]

    @staticmethod
    def _get_default_policy() -> GlobalSessionPolicy:
        for policy in signon_client.global_session_policies.values():
            if policy.is_default or policy.name == "Default Policy":
                return policy
        return GlobalSessionPolicy(
            id="default-policy-missing",
            name="Default Policy",
            priority=1,
            status="MISSING",
            is_default=True,
            rules=[],
        )
