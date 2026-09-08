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

    def _paginate_web_acls(self, client, scope):
        """Yield every Web ACL summary in the given scope, following NextMarker to the last page.

        ListWebACLs returns at most 100 Web ACLs per call and sets NextMarker while more remain,
        so a single call silently drops every Web ACL past the first page. The rationale for the
        hand-rolled loop and its two guards is in the comment below.
        """
        # ListWebACLs returns at most 100 Web ACLs per call and WAFv2 ships no botocore
        # paginator (verified at pin 1.40.61), so hand-rolling is required. The documented
        # contract (ListWebACLs API reference) states NextMarker appears only when more
        # objects remain, so the loop follows the marker. The seen-set guard protects
        # against a marker that never clears; the iteration cap (1000 pages = 100K Web ACLs
        # max at the 100-per-page limit) can only fire on a misbehaving API, since the
        # default WebACLs-per-region quota is far below that threshold.
        next_marker = None
        seen_markers = set()
        max_iterations = 1000
        iterations = 0

        repeated_marker = False

        while iterations < max_iterations:
            iterations += 1
            kwargs = {"Scope": scope}
            if next_marker:
                if next_marker in seen_markers:
                    repeated_marker = True
                    logger.error(
                        f"WAFv2 - ListWebACLs pagination loop detected at marker {next_marker} for scope {scope}"
                    )
                    break
                seen_markers.add(next_marker)
                kwargs["NextMarker"] = next_marker

            response = client.list_web_acls(**kwargs)
            web_acls = response.get("WebACLs", [])
            yield from web_acls

            next_marker = response.get("NextMarker")
            if not next_marker:
                break

        # Which exit happened has to be tracked, not inferred from the counter. A repeated marker seen
        # on the 1000th entry increments iterations to the cap before breaking, and leaves next_marker
        # truthy, so the count-and-marker test below fired too and the log named the page cap as the
        # cause of a stop the loop guard had actually caused -- two contradictory errors for one exit,
        # after 999 calls rather than 1000. The counter cannot distinguish the two exits because both
        # reach it with the same values; only the flag can.
        if not repeated_marker and iterations >= max_iterations and next_marker:
            logger.error(
                f"WAFv2 - ListWebACLs pagination hit the {max_iterations}-page cap for scope {scope}; "
                "results may be truncated"
            )

    def _list_web_acls_global(self):
        """List CLOUDFRONT-scoped Web ACLs and populate the web_acls dictionary."""
        logger.info("WAFv2 - Listing Global Web ACLs...")
        try:
            for wafv2 in self._paginate_web_acls(self.client, "CLOUDFRONT"):
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
        """List REGIONAL-scoped Web ACLs for the given region and populate the web_acls dictionary."""
        logger.info("WAFv2 - Listing Regional Web ACLs...")
        try:
            for wafv2 in self._paginate_web_acls(regional_client, "REGIONAL"):
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
