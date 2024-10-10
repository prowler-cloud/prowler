from enum import Enum
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class WAFv2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.web_acls = {}
        self._list_web_acls_global()
        self.__threading_call__(self._list_web_acls_regional)
        self.__threading_call__(self._list_rule_groups, self.web_acls.values())
        self.__threading_call__(self._get_rule_group, self.web_acls.values())
        self.__threading_call__(self._get_web_acl, self.web_acls.values())
        self.__threading_call__(
            self._list_resources_for_web_acl, self.web_acls.values()
        )
        self.__threading_call__(self._get_logging_configuration, self.web_acls.values())
        self.__threading_call__(self._list_tags, self.web_acls.values())

    def _list_web_acls_global(self):
        logger.info("WAFv2 - Listing Global Web ACLs...")
        try:
            regional_client = self.regional_clients["us-east-1"]
            for wafv2 in regional_client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]:
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
                        region="us-east-1",
                    )
        except Exception as error:
            logger.error(
                f"us-east-1 -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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

    def _list_rule_groups(self, acl):
        logger.info("WAFv2 - Listing Rule Groups...")
        try:
            rule_groups = (
                self.regional_clients[acl.region]
                .list_rule_groups(Scope=acl.scope.value)
                .get("RuleGroups", [])
            )
            for rule_group in rule_groups:
                name = rule_group.get("Name", "")
                id = rule_group.get("Id", "")
                arn = rule_group.get("ARN", "")
                acl.rule_groups.append(
                    RuleGroup(name=name, id=id, arn=arn, scope=acl.scope)
                )

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_rule_group(self, acl):
        logger.info("WAFv2 - Getting Rule Group...")
        try:
            for rule_group in acl.rule_groups:
                get_rule_group = (
                    self.regional_clients[acl.region]
                    .get_rule_group(
                        Name=rule_group.name,
                        Id=rule_group.id,
                        Scope=rule_group.scope.value,
                        ARN=rule_group.arn,
                    )
                    .get("RuleGroup", {})
                )

                rule_group.cloudwatch_metrics_enabled = get_rule_group.get(
                    "VisibilityConfig", {}
                ).get("CloudWatchMetricsEnabled", False)

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_logging_configuration(self, acl):
        logger.info("WAFv2 - Get Logging Configuration...")
        try:
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
            scope = acl.scope.value
            get_web_acl = self.regional_clients[acl.region].get_web_acl(
                Name=acl.name, Scope=scope, Id=acl.id
            )
            # Pre-Process Firewall Manager Rule Groups
            try:
                pre_rule_groups = get_web_acl.get("WebACL", {}).get(
                    "PreProcessFirewallManagerRuleGroups", []
                )
                for group in pre_rule_groups:
                    name = group.get("Name", "")
                    metrics_enabled = group.get("VisibilityConfig", {}).get(
                        "CloudWatchMetricsEnabled", False
                    )
                    acl.pre_process_firewall_rule_groups.append(
                        FirewallManagerRuleGroup(
                            name=name, cloudwatch_metrics_enabled=metrics_enabled
                        )
                    )

            except Exception as error:
                logger.warning(
                    f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

            # Post-Process Firewall Manager Rule Groups
            try:
                post_rule_groups = get_web_acl.get("WebACL", {}).get(
                    "PostProcessFirewallManagerRuleGroups", []
                )
                for group in post_rule_groups:
                    name = group.get("Name", "")
                    metrics_enabled = group.get("VisibilityConfig", {}).get(
                        "CloudWatchMetricsEnabled", False
                    )
                    acl.post_process_firewall_rule_groups.append(
                        FirewallManagerRuleGroup(
                            name=name, cloudwatch_metrics_enabled=metrics_enabled
                        )
                    )

            except Exception as error:
                logger.warning(
                    f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

            # Rules
            try:
                rules = get_web_acl.get("WebACL", {}).get("Rules", [])
                for rule in rules:
                    name = rule.get("Name", "")
                    metrics_enabled = rule.get("VisibilityConfig", {}).get(
                        "CloudWatchMetricsEnabled", False
                    )
                    acl.rules.append(
                        Rule(name=name, cloudwatch_metrics_enabled=metrics_enabled)
                    )
            except Exception as error:
                logger.warning(
                    f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags(self, resource: any):
        logger.info("WAFv2 - Listing tags...")
        try:
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


class RuleGroup(BaseModel):
    """Model representing a rule group for the Web ACL."""

    name: str
    id: str
    arn: str
    scope: Scope = Scope.REGIONAL
    cloudwatch_metrics_enabled: bool = False


class FirewallManagerRuleGroup(BaseModel):
    """Model representing a rule group for the Web ACL."""

    name: str
    cloudwatch_metrics_enabled: bool = False


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
    pre_process_firewall_rule_groups: list[Rule] = []
    post_process_firewall_rule_groups: list[Rule] = []
    rule_groups: list[RuleGroup] = []
    rules: list[Rule] = []
