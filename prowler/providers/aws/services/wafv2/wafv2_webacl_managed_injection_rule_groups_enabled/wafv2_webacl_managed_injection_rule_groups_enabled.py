from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client
from prowler.providers.aws.services.wafv2.wafv2_service import ManagedRuleGroup, Scope

AWS_MANAGED_RULE_GROUP_VENDOR = "AWS"
REQUIRED_INJECTION_RULE_GROUPS = (
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
)
# Overriding a rule to Block keeps it blocking; any other override (Count,
# Allow, Captcha or Challenge) stops the rule from blocking what it matches.
BLOCKING_RULE_ACTION = "Block"
# Allow terminates rule evaluation, so a rule overridden to Allow in one
# reference lets matching requests skip every later reference of the group.
TERMINATING_ALLOW_ACTION = "Allow"


def _non_blocking_rule_overrides(
    managed_rule_group: ManagedRuleGroup,
) -> dict[str, str]:
    """Return the rules of a managed rule group that no longer block.

    Args:
        managed_rule_group: Managed rule group referenced by a Web ACL rule.

    Returns:
        Rule names mapped to the action they were overridden to. Legacy
        ``ExcludedRules`` set the rule action to Count, so they are reported
        as Count overrides.
    """
    overrides = {name: "Count" for name in managed_rule_group.excluded_rules}
    overrides.update(
        {
            name: action
            for name, action in managed_rule_group.rule_action_overrides.items()
            if action != BLOCKING_RULE_ACTION
        }
    )
    return overrides


def _format_rule_overrides(overrides: dict[str, set[str]]) -> str:
    """Format rule overrides as ``SQLi_BODY, SQLi_COOKIE overridden to Count``.

    Args:
        overrides: Rule names mapped to every action they were overridden to
            across the references of the rule group.

    Returns:
        The overridden rules grouped by action, actions joined with ``and``.
        A rule overridden to several actions is listed under each of them.
    """
    rules_by_action = defaultdict(list)
    for rule_name, actions in overrides.items():
        for action in actions:
            rules_by_action[action].append(rule_name)
    return " and ".join(
        f"{', '.join(sorted(rule_names))} overridden to {action}"
        for action, rule_names in sorted(rules_by_action.items())
    )


class wafv2_webacl_managed_injection_rule_groups_enabled(Check):
    """Ensure WAFv2 Web ACLs enforce the AWS managed injection rule groups.

    A Web ACL passes when both ``AWSManagedRulesSQLiRuleSet`` and
    ``AWSManagedRulesKnownBadInputsRuleSet`` are referenced by one of its
    rules, directly or through an AWS Firewall Manager rule group, with the
    group's rule actions left in place. A group missing or overridden to
    ``Count`` as a whole fails, since a counted rule group only records
    matches and blocks nothing. A group whose individual rules are overridden
    to a non-blocking action, or that only inspects the requests matching a
    scope-down statement, is reported for manual review: without the group's
    rule catalog and the traffic it fronts the check cannot tell a partial
    exception from a wholesale exclusion, and it must not emit a false PASS.
    A group with a rule overridden to ``Allow`` in any reference is never
    counted as enforced through another reference: ``Allow`` terminates
    evaluation, so whether the other reference still sees those requests
    depends on the evaluation order (Firewall Manager pre-process groups and
    rule priorities), which the check does not evaluate.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check.

        Returns:
            One PASS, FAIL or MANUAL report per Web ACL whose rules were read,
            plus a single account-level MANUAL report when Web ACLs could not
            be listed in some scope or their rules could not be retrieved.
        """
        findings = []
        unreadable_web_acls = []

        for web_acl in wafv2_client.web_acls.values():
            if not web_acl.rules_retrieved:
                unreadable_web_acls.append(web_acl)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            enforced = set()
            counted = set()
            # Required rule group -> its rules mapped to the non-blocking
            # actions they are overridden to, across all references.
            overridden_rules = {}
            # Required rule groups referenced with a scope-down statement.
            scoped = set()
            # Required rule groups with a rule overridden to Allow.
            allow_overridden = set()
            for rule in web_acl.rules + web_acl.rule_groups:
                managed_rule_group = rule.managed_rule_group
                if not (
                    managed_rule_group
                    and managed_rule_group.vendor_name == AWS_MANAGED_RULE_GROUP_VENDOR
                    and managed_rule_group.name in REQUIRED_INJECTION_RULE_GROUPS
                ):
                    continue
                if rule.overridden_to_count:
                    counted.add(managed_rule_group.name)
                    continue
                rule_overrides = _non_blocking_rule_overrides(managed_rule_group)
                if rule_overrides:
                    group_overrides = overridden_rules.setdefault(
                        managed_rule_group.name, {}
                    )
                    for rule_name, action in rule_overrides.items():
                        group_overrides.setdefault(rule_name, set()).add(action)
                        if action == TERMINATING_ALLOW_ACTION:
                            allow_overridden.add(managed_rule_group.name)
                if managed_rule_group.scope_down_statement:
                    scoped.add(managed_rule_group.name)
                if not rule_overrides and not managed_rule_group.scope_down_statement:
                    enforced.add(managed_rule_group.name)

            failures = []
            details = []
            for rule_group_name in REQUIRED_INJECTION_RULE_GROUPS:
                if (
                    rule_group_name in enforced
                    and rule_group_name not in allow_overridden
                ):
                    continue
                limitations = []
                if rule_group_name in overridden_rules:
                    limitations.append(
                        f"has {_format_rule_overrides(overridden_rules[rule_group_name])}"
                    )
                if rule_group_name in scoped:
                    limitations.append(
                        "only inspects requests matching a scope-down statement"
                    )
                if limitations:
                    detail = f"{rule_group_name} {' and '.join(limitations)}"
                else:
                    detail = (
                        f"{rule_group_name} is overridden to Count"
                        if rule_group_name in counted
                        else f"{rule_group_name} is missing"
                    )
                    failures.append(detail)
                details.append(detail)

            if failures:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} does not enforce the AWS "
                    f"managed injection rule groups: {'; '.join(details)}."
                )
            elif details:
                report.status = "MANUAL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} enables the AWS managed "
                    f"injection rule groups but limits them "
                    f"({'; '.join(details)}); verify that they still provide "
                    f"the required injection protection."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} enforces the AWS managed "
                    f"injection rule groups "
                    f"{' and '.join(REQUIRED_INJECTION_RULE_GROUPS)}."
                )

            findings.append(report)

        problems = []
        failed_scopes = wafv2_client.web_acls_list_failed_scopes
        if failed_scopes:
            problems.append(
                f"Web ACLs could not be listed in {', '.join(sorted(failed_scopes))}, "
                f"verify that wafv2:ListWebACLs is granted to the scanning identity"
            )
        if unreadable_web_acls:
            unreadable_names = sorted(
                f"{web_acl.name} ({web_acl.scope.value}:{web_acl.region})"
                for web_acl in unreadable_web_acls
            )
            cloudfront_hint = (
                " and that us-east-1 is included in the scan for CLOUDFRONT Web ACLs"
                if any(
                    web_acl.scope == Scope.CLOUDFRONT for web_acl in unreadable_web_acls
                )
                else ""
            )
            problems.append(
                f"rules could not be retrieved for Web ACLs "
                f"{', '.join(unreadable_names)}, verify that wafv2:GetWebACL is "
                f"granted to the scanning identity{cloudfront_hint}"
            )

        if problems:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = wafv2_client.region
            report.resource_id = wafv2_client.audited_account
            report.resource_arn = wafv2_client.audited_account_arn
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate AWS WAFv2 managed injection rule groups: "
                f"{'; '.join(problems)}."
            )
            findings.append(report)

        return findings
