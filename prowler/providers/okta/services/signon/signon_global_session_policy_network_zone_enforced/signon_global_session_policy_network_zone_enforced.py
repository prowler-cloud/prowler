from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy


class signon_global_session_policy_network_zone_enforced(Check):
    """STIG V-279691 / OKTA-APP-003242.

    The DISA STIG requires the Default Global Session Policy to use an
    "IF User's IP is" condition mapped to a Network Zone on at least one
    active non-default rule, so access can be allowed or denied per the
    organization's Access Control Policy.
    """

    def execute(self) -> list[CheckReportOkta]:
        org_domain = signon_client.provider.identity.org_domain
        policy = self._get_default_policy()
        report = CheckReportOkta(
            metadata=self.metadata(), resource=policy, org_domain=org_domain
        )

        if policy.id == "default-policy-missing":
            report.status = "FAIL"
            report.status_extended = (
                "Default Global Session Policy was not found. STIG V-279691 "
                "requires the Default Policy to apply an IP-based Network "
                "Zone condition on at least one active non-default rule."
            )
            return [report]

        if policy.status and policy.status.upper() != "ACTIVE":
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' is in "
                f"status '{policy.status}'. STIG V-279691 requires an active "
                "Default Policy with an IP-based Network Zone condition."
            )
            return [report]

        rules_with_zones = [
            rule
            for rule in policy.rules
            if (not rule.status or rule.status.upper() == "ACTIVE")
            and not rule.is_default
            and rule.name != "Default Rule"
            and (rule.network_zones_include or rule.network_zones_exclude)
        ]

        if not rules_with_zones:
            report.status = "FAIL"
            report.status_extended = (
                f"Default Global Session Policy '{policy.name}' has no active "
                "non-default rule mapping User's IP to a Network Zone. The "
                "policy cannot allow or deny access based on the organization's "
                "Access Control Policy."
            )
            return [report]

        rule_names = ", ".join(f"'{rule.name}'" for rule in rules_with_zones)
        report.status = "PASS"
        report.status_extended = (
            f"Default Global Session Policy '{policy.name}' uses Network Zone "
            f"conditions on the following active non-default rule(s): {rule_names}."
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
