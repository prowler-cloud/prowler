from enum import Enum
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class WAFv2(AWSService):
    def __init__(self, provider):
        # AWS WAFv2 is available globally for CloudFront distributions, but you must use the Region US East (N. Virginia) to create your web ACL.
        region = "us-east-1" if provider.identity.partition == "aws" else None
        super().__init__(__class__.__name__, provider, region=region)
        self.web_acls = {}
        if self.audited_partition == "aws":
            self._list_web_acls_global()
        self.__threading_call__(self._list_web_acls_regional)
        self.__threading_call__(self._get_web_acl, self.web_acls.values())
        self.__threading_call__(
            self._list_resources_for_web_acl, self.web_acls.values()
        )
        self.__threading_call__(self._get_logging_configuration, self.web_acls.values())
        self.__threading_call__(self._list_tags, self.web_acls.values())

    def _list_web_acls_global(self):
        logger.info("WAFv2 - Listing Global Web ACLs...")
        try:
            for wafv2 in self.client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(wafv2["ARN"], self.audit_resources)
                ):
                    arn = wafv2["ARN"]
                    self.web_acls[arn] = WebAclv2(
                        arn=arn,
                        name=wafv2["Name"],
                        id=wafv2["Id"],
                        albs=[],
                        user_pools=[],
                        scope=Scope.CLOUDFRONT,
                        region=self.region,
                    )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_web_acls_regional(self, regional_client):
        logger.info("WAFv2 - Listing Regional Web ACLs...")
        try:
            for wafv2 in regional_client.list_web_acls(Scope="REGIONAL")["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(wafv2["ARN"], self.audit_resources)
                ):
                    arn = wafv2["ARN"]
                    self.web_acls[arn] = WebAclv2(
                        arn=arn,
                        name=wafv2["Name"],
                        id=wafv2["Id"],
                        albs=[],
                        user_pools=[],
                        scope=Scope.REGIONAL,
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_logging_configuration(self, acl):
        logger.info("WAFv2 - Get Logging Configuration...")
        try:
            if acl.scope == Scope.REGIONAL or acl.region in self.regional_clients:
                logging_enabled = self.regional_clients[
                    acl.region
                ].get_logging_configuration(ResourceArn=acl.arn)
                acl.logging_enabled = bool(
                    logging_enabled["LoggingConfiguration"]["LogDestinationConfigs"]
                )

        except ClientError as error:
            if error.response["Error"]["Code"] == "WAFNonexistentItemException":
                logger.warning(
                    f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_resources_for_web_acl(self, acl):
        logger.info("WAFv2 - Describing resources...")
        try:
            if acl.scope == Scope.REGIONAL:
                for resource in self.regional_clients[
                    acl.region
                ].list_resources_for_web_acl(
                    WebACLArn=acl.arn, ResourceType="APPLICATION_LOAD_BALANCER"
                )[
                    "ResourceArns"
                ]:
                    acl.albs.append(resource)

                for resource in self.regional_clients[
                    acl.region
                ].list_resources_for_web_acl(
                    WebACLArn=acl.arn, ResourceType="COGNITO_USER_POOL"
                )[
                    "ResourceArns"
                ]:
                    acl.user_pools.append(resource)

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_web_acl(self, acl: str):
        logger.info("WAFv2 - Getting Web ACL...")
        try:
            if acl.scope == Scope.REGIONAL or acl.region in self.regional_clients:
                scope = acl.scope.value
                get_web_acl = self.regional_clients[acl.region].get_web_acl(
                    Name=acl.name, Scope=scope, Id=acl.id
                )

                try:
                    rules = get_web_acl.get("WebACL", {}).get("Rules", [])
                    for rule in rules:
                        new_rule = Rule(
                            name=rule.get("Name", ""),
                            cloudwatch_metrics_enabled=rule.get(
                                "VisibilityConfig", {}
                            ).get("CloudWatchMetricsEnabled", False),
                        )
                        if (
                            rule.get("Statement", {})
                            .get("RuleGroupReferenceStatement", {})
                            .get("ARN")
                        ):
                            acl.rule_groups.append(new_rule)
                        else:
                            acl.rules.append(new_rule)

                        # Recursively parse the rule statement to retain managed rule
                        # groups (vendor/name/overrides/exclusions) and detect custom
                        # XssMatchStatements, including nested statements.
                        override_to_count = "Count" in rule.get(
                            "OverrideAction", {}
                        )
                        rule_blocks = self._rule_action_blocks(rule.get("Action", {}))
                        has_xss = self._parse_statement(
                            rule.get("Statement", {}),
                            acl,
                            override_to_count,
                        )
                        if has_xss and rule_blocks:
                            acl.rules_with_xss_match.append(new_rule.name)

                    firewall_manager_managed_rg = get_web_acl.get("WebACL", {}).get(
                        "PreProcessFirewallManagerRuleGroups", []
                    ) + get_web_acl.get("WebACL", {}).get(
                        "PostProcessFirewallManagerRuleGroups", []
                    )

                    for rule in firewall_manager_managed_rg:
                        acl.rule_groups.append(
                            Rule(
                                name=rule.get("Name", ""),
                                cloudwatch_metrics_enabled=rule.get(
                                    "VisibilityConfig", {}
                                ).get("CloudWatchMetricsEnabled", False),
                            )
                        )

                except Exception as error:
                    logger.error(
                        f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _rule_action_blocks(action: dict) -> bool:
        """Return True if a custom rule action blocks or challenges the request.

        Count and Allow actions do not protect against a matched request, so a rule with
        those actions is not considered active protection.
        """
        if not action:
            # Managed rule group / rule group reference rules use OverrideAction instead of
            # Action; a custom XssMatchStatement rule must define an Action, so an empty
            # Action means this is not an effective custom protection rule.
            return False
        return any(effective in action for effective in ("Block", "Captcha", "Challenge"))

    def _parse_statement(self, statement: dict, acl, override_to_count: bool) -> bool:
        """Recursively walk a rule Statement.

        Retains any managed rule groups found on the given ``acl`` and returns whether an
        ``XssMatchStatement`` was found anywhere in the (possibly nested) statement tree.
        """
        found_xss = False
        if not isinstance(statement, dict):
            return False

        if "XssMatchStatement" in statement:
            found_xss = True

        managed = statement.get("ManagedRuleGroupStatement")
        if managed:
            excluded_rules = [
                excluded.get("Name")
                for excluded in managed.get("ExcludedRules", [])
                if excluded.get("Name")
            ]
            for override in managed.get("RuleActionOverrides", []):
                if "Count" in override.get("ActionToUse", {}) and override.get("Name"):
                    excluded_rules.append(override["Name"])
            acl.managed_rule_groups.append(
                ManagedRuleGroup(
                    vendor_name=managed.get("VendorName", ""),
                    name=managed.get("Name", ""),
                    override_to_count=override_to_count,
                    excluded_rules=excluded_rules,
                )
            )
            if managed.get("ScopeDownStatement"):
                found_xss = (
                    self._parse_statement(
                        managed["ScopeDownStatement"], acl, override_to_count
                    )
                    or found_xss
                )

        for logical in ("AndStatement", "OrStatement"):
            if logical in statement:
                for sub_statement in statement[logical].get("Statements", []):
                    found_xss = (
                        self._parse_statement(sub_statement, acl, override_to_count)
                        or found_xss
                    )

        if "NotStatement" in statement:
            found_xss = (
                self._parse_statement(
                    statement["NotStatement"].get("Statement", {}),
                    acl,
                    override_to_count,
                )
                or found_xss
            )

        rate_based = statement.get("RateBasedStatement", {})
        if rate_based.get("ScopeDownStatement"):
            found_xss = (
                self._parse_statement(
                    rate_based["ScopeDownStatement"], acl, override_to_count
                )
                or found_xss
            )

        return found_xss

    def _list_tags(self, resource: any):
        logger.info("WAFv2 - Listing tags...")
        try:
            if (
                resource.scope == Scope.REGIONAL
                or resource.region in self.regional_clients
            ):
                resource.tags = (
                    self.regional_clients[resource.region]
                    .list_tags_for_resource(ResourceARN=resource.arn)
                    .get("TagInfoForResource", {})
                    .get("TagList", [])
                )
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Scope(Enum):
    """Enumeration for the scope of the Web ACL."""

    REGIONAL = "REGIONAL"
    CLOUDFRONT = "CLOUDFRONT"


class Rule(BaseModel):
    """Model representing a rule for the Web ACL."""

    name: str
    cloudwatch_metrics_enabled: bool = False


class ManagedRuleGroup(BaseModel):
    """Model representing an AWS/Marketplace managed rule group referenced by a Web ACL."""

    vendor_name: str
    name: str
    # Whether the whole rule group action is overridden to Count (i.e. excluded wholesale
    # from blocking) via the rule's OverrideAction.
    override_to_count: bool = False
    # Names of individual rules within the group that are excluded from blocking, either via
    # (deprecated) ExcludedRules or via RuleActionOverrides that set the action to Count.
    excluded_rules: list[str] = []


class WebAclv2(BaseModel):
    """Model representing a Web ACL for WAFv2."""

    arn: str
    name: str
    id: str
    albs: list[str]
    user_pools: list[str]
    region: str
    logging_enabled: bool = False
    tags: Optional[list]
    scope: Scope = Scope.REGIONAL
    rules: list[Rule] = []
    rule_groups: list[Rule] = []
    # Managed rule groups (AWS/Marketplace) referenced by the Web ACL, collected recursively.
    managed_rule_groups: list[ManagedRuleGroup] = []
    # Names of custom rules that contain an XssMatchStatement (found recursively) and whose
    # action blocks/challenges the request (Block, Captcha or Challenge).
    rules_with_xss_match: list[str] = []
