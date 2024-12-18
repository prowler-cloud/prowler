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
        if self.audited_partition == "aws":
            # AWS WAFv2 is available globally for CloudFront distributions, but you must use the Region US East (N. Virginia) to create your web ACL.
            self.region = "us-east-1"
            self.client = self.session.client(self.service, self.region)
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
