from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

# The AWS Core rule set includes cross-site scripting (XSS) protection rules.
XSS_MANAGED_RULE_GROUP = "AWSManagedRulesCommonRuleSet"


class wafv2_webacl_xss_protection_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            # XSS protection via the AWS Core rule set (which contains the
            # CrossSiteScripting_* rules), enabled and not excluded wholesale.
            managed_xss_enabled = any(
                managed_rule_group.vendor_name == "AWS"
                and managed_rule_group.name == XSS_MANAGED_RULE_GROUP
                and not managed_rule_group.override_to_count
                for managed_rule_group in web_acl.managed_rule_groups
            )

            # XSS protection via a custom XssMatchStatement rule that blocks/challenges.
            custom_xss_enabled = bool(web_acl.rules_with_xss_match)

            if managed_xss_enabled or custom_xss_enabled:
                report.status = "PASS"
                if managed_xss_enabled and custom_xss_enabled:
                    protection = (
                        f"the {XSS_MANAGED_RULE_GROUP} managed rule group and custom "
                        "XssMatchStatement rules"
                    )
                elif managed_xss_enabled:
                    protection = f"the {XSS_MANAGED_RULE_GROUP} managed rule group"
                else:
                    protection = "custom XssMatchStatement rules"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} has XSS protection enabled through "
                    f"{protection}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} does not have XSS protection enabled."
                )

            findings.append(report)

        return findings
