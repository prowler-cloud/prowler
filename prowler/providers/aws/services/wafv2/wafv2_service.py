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
        """Yield every Web ACL summary in the given scope, following NextMarker to the last page."""
        # WAFv2 ships no botocore paginator; the seen set stops an API that repeats a marker.
        kwargs = {"Scope": scope}
        seen_markers = set()
        while True:
            response = client.list_web_acls(**kwargs)
            yield from response.get("WebACLs", [])
            next_marker = response.get("NextMarker")
            if not next_marker:
                break
            if next_marker in seen_markers:
                logger.error(
                    f"WAFv2 - ListWebACLs pagination loop detected at marker {next_marker} for scope {scope}"
                )
                break
            seen_markers.add(next_marker)
            kwargs["NextMarker"] = next_marker

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

    def _get_client_for_web_acl(self, acl):
        """Return the client that serves the Web ACL's scope.

        CLOUDFRONT-scoped Web ACLs are only reachable through us-east-1, which is
        self.client and may not be an audited region in regional_clients.
        """
        if acl.scope == Scope.CLOUDFRONT:
            return self.client
        return self.regional_clients[acl.region]

    def _get_logging_configuration(self, acl):
        logger.info("WAFv2 - Get Logging Configuration...")
        try:
            logging_enabled = self._get_client_for_web_acl(
                acl
            ).get_logging_configuration(ResourceArn=acl.arn)
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
            get_web_acl = self._get_client_for_web_acl(acl).get_web_acl(
                Name=acl.name, Scope=acl.scope.value, Id=acl.id
            )

            try:
                rules = get_web_acl.get("WebACL", {}).get("Rules", [])
                for rule in rules:
                    managed_statement = rule.get("Statement", {}).get(
                        "ManagedRuleGroupStatement"
                    )
                    new_rule = Rule(
                        name=rule.get("Name", ""),
                        cloudwatch_metrics_enabled=rule.get("VisibilityConfig", {}).get(
                            "CloudWatchMetricsEnabled", False
                        ),
                        managed_rule_group=(
                            ManagedRuleGroup(
                                vendor_name=managed_statement.get("VendorName", ""),
                                name=managed_statement.get("Name", ""),
                                version=managed_statement.get("Version", ""),
                            )
                            if managed_statement
                            else None
                        ),
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
            resource.tags = (
                self._get_client_for_web_acl(resource)
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


class ManagedRuleGroup(BaseModel):
    """Managed rule group referenced by a Web ACL rule."""

    vendor_name: str
    name: str
    version: str = ""


class Rule(BaseModel):
    """Model representing a rule for the Web ACL."""

    name: str
    cloudwatch_metrics_enabled: bool = False
    managed_rule_group: Optional[ManagedRuleGroup] = None


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
