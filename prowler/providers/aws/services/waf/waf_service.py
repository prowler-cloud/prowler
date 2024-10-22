from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class WAF(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("waf", provider)
        self.rules = {}
        self.rule_groups = {}
        self.web_acls = {}
        if self.audited_partition == "aws":
            # AWS WAF is available globally for CloudFront distributions, but you must use the Region US East (N. Virginia) to create your web ACL and any resources used in the web ACL, such as rule groups, IP sets, and regex pattern sets.
            self.region = "us-east-1"
            self.client = self.session.client(self.service, self.region)
            self._list_rules()
            self.__threading_call__(self._get_rule, self.rules.values())
            self._list_rule_groups()
            self.__threading_call__(
                self._list_activated_rules_in_rule_group, self.rule_groups.values()
            )
            self._list_web_acls()
            self.__threading_call__(self._get_web_acl, self.web_acls.values())
            self.__threading_call__(
                self._get_logging_configuration, self.web_acls.values()
            )

    def _list_rules(self):
        logger.info("WAF - Listing Global Rules...")
        try:
            for rule in self.client.list_rules().get("Rules", []):
                arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:rule/{rule['RuleId']}"
                self.rules[arn] = Rule(
                    arn=arn,
                    id=rule.get("RuleId", ""),
                    region=self.region,
                    name=rule.get("Name", ""),
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_rule(self, rule):
        logger.info(f"WAF - Getting Global Rule {rule.name}...")
        try:
            get_rule = self.client.get_rule(RuleId=rule.id)
            for predicate in get_rule.get("Rule", {}).get("Predicates", []):
                rule.predicates.append(
                    Predicate(
                        negated=predicate.get("Negated", False),
                        type=predicate.get("Type", "IPMatch"),
                        data_id=predicate.get("DataId", ""),
                    )
                )

        except Exception as error:
            logger.error(
                f"{rule.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_rule_groups(self):
        logger.info("WAF - Listing Global Rule Groups...")
        try:
            for rule_group in self.client.list_rule_groups().get("RuleGroups", []):
                arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:rulegroup/{rule_group['RuleGroupId']}"
                self.rule_groups[arn] = RuleGroup(
                    arn=arn,
                    region=self.region,
                    id=rule_group.get("RuleGroupId", ""),
                    name=rule_group.get("Name", ""),
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_activated_rules_in_rule_group(self, rule_group):
        logger.info(
            f"WAF - Listing activated rules in Global Rule Group {rule_group.name}..."
        )
        try:
            for rule in self.client.list_activated_rules_in_rule_group(
                RuleGroupId=rule_group.id
            ).get("ActivatedRules", []):
                rule_arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:rule/{rule.get('RuleId', '')}"
                rule_group.rules.append(self.rules[rule_arn])

        except Exception as error:
            logger.error(
                f"{rule_group.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_web_acls(self):
        logger.info("WAF - Listing Global Web ACLs...")
        try:
            for waf in self.client.list_web_acls()["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(waf["WebACLId"], self.audit_resources)
                ):
                    arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:webacl/{waf['WebACLId']}"
                    self.web_acls[arn] = WebAcl(
                        arn=arn,
                        name=waf["Name"],
                        id=waf["WebACLId"],
                        albs=[],
                        region=self.region,
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_web_acl(self, acl):
        logger.info(f"WAF - Getting Global Web ACL {acl.name}...")
        try:
            get_web_acl = self.client.get_web_acl(WebACLId=acl.id)
            for rule in get_web_acl.get("WebACL", {}).get("Rules", []):
                rule_id = rule.get("RuleId", "")
                if rule.get("Type", "") == "GROUP":
                    rule_group_arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:rulegroup/{rule_id}"
                    acl.rule_groups.append(self.rule_groups[rule_group_arn])
                else:
                    rule_arn = f"arn:{self.audited_partition}:waf:{self.region}:{self.audited_account}:rule/{rule_id}"
                    acl.rules.append(self.rules[rule_arn])

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_logging_configuration(self, acl):
        logger.info(f"WAF - Getting Global Web ACL {acl.name} logging configuration...")
        try:
            get_logging_configuration = self.client.get_logging_configuration(
                ResourceArn=acl.arn
            )
            acl.logging_enabled = bool(
                get_logging_configuration.get("LoggingConfiguration", {}).get(
                    "LogDestinationConfigs", []
                )
            )

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class WAFRegional(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("waf-regional", provider)
        self.rules = {}
        self.rule_groups = {}
        self.web_acls = {}
        self.__threading_call__(self._list_rules)
        self.__threading_call__(self._get_rule, self.rules.values())
        self.__threading_call__(self._list_rule_groups)
        self.__threading_call__(
            self._list_activated_rules_in_rule_group, self.rule_groups.values()
        )
        self.__threading_call__(self._list_web_acls)
        self.__threading_call__(self._get_web_acl, self.web_acls.values())
        self.__threading_call__(self._list_resources_for_web_acl)

    def _list_rules(self, regional_client):
        logger.info("WAFRegional - Listing Regional Rules...")
        try:
            for rule in regional_client.list_rules().get("Rules", []):
                arn = f"arn:{self.audited_partition}:waf-regional:{regional_client.region}:{self.audited_account}:rule/{rule['RuleId']}"
                self.rules[arn] = Rule(
                    arn=arn,
                    id=rule.get("RuleId", ""),
                    region=regional_client.region,
                    name=rule.get("Name", ""),
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_rule(self, rule):
        logger.info(f"WAFRegional - Getting Rule {rule.name}...")
        try:
            get_rule = self.regional_clients[rule.region].get_rule(RuleId=rule.id)
            for predicate in get_rule.get("Rule", {}).get("Predicates", []):
                rule.predicates.append(
                    Predicate(
                        negated=predicate.get("Negated", False),
                        type=predicate.get("Type", "IPMatch"),
                        data_id=predicate.get("DataId", ""),
                    )
                )
        except Exception as error:
            logger.error(
                f"{rule.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_rule_groups(self, regional_client):
        logger.info("WAFRegional - Listing Regional Rule Groups...")
        try:
            for rule_group in regional_client.list_rule_groups().get("RuleGroups", []):
                arn = f"arn:{self.audited_partition}:waf-regional:{regional_client.region}:{self.audited_account}:rulegroup/{rule_group['RuleGroupId']}"
                self.rule_groups[arn] = RuleGroup(
                    arn=arn,
                    region=regional_client.region,
                    id=rule_group.get("RuleGroupId", ""),
                    name=rule_group.get("Name", ""),
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_activated_rules_in_rule_group(self, rule_group):
        logger.info(
            f"WAFRegional - Listing activated rules in Rule Group {rule_group.name}..."
        )
        try:
            for rule in (
                self.regional_clients[rule_group.region]
                .list_activated_rules_in_rule_group(RuleGroupId=rule_group.id)
                .get("ActivatedRules", [])
            ):
                rule_arn = f"arn:{self.audited_partition}:waf-regional:{rule_group.region}:{self.audited_account}:rule/{rule.get('RuleId', '')}"
                rule_group.rules.append(self.rules[rule_arn])

        except Exception as error:
            logger.error(
                f"{rule_group.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_web_acls(self, regional_client):
        logger.info("WAFRegional - Listing Regional Web ACLs...")
        try:
            for waf in regional_client.list_web_acls()["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(waf["WebACLId"], self.audit_resources)
                ):
                    arn = f"arn:{self.audited_partition}:waf-regional:{regional_client.region}:{self.audited_account}:webacl/{waf['WebACLId']}"
                    self.web_acls[arn] = WebAcl(
                        arn=arn,
                        name=waf["Name"],
                        id=waf["WebACLId"],
                        albs=[],
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_web_acl(self, acl):
        logger.info(f"WAFRegional - Getting Regional Web ACL {acl.name}...")
        try:
            get_web_acl = self.regional_clients[acl.region].get_web_acl(WebACLId=acl.id)
            for rule in get_web_acl.get("WebACL", {}).get("Rules", []):
                rule_id = rule.get("RuleId", "")
                if rule.get("Type", "") == "GROUP":
                    rule_group_arn = f"arn:{self.audited_partition}:waf-regional:{acl.region}:{self.audited_account}:rulegroup/{rule_id}"
                    acl.rule_groups.append(self.rule_groups[rule_group_arn])
                else:
                    rule_arn = f"arn:{self.audited_partition}:waf-regional:{acl.region}:{self.audited_account}:rule/{rule_id}"
                    acl.rules.append(self.rules[rule_arn])

        except Exception as error:
            logger.error(
                f"{acl.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_resources_for_web_acl(self, regional_client):
        logger.info("WAFRegional - Describing resources...")
        try:
            for acl in self.web_acls.values():
                if acl.region == regional_client.region:
                    for resource in regional_client.list_resources_for_web_acl(
                        WebACLId=acl.id, ResourceType="APPLICATION_LOAD_BALANCER"
                    ).get("ResourceArns", []):
                        acl.albs.append(resource)

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Predicate(BaseModel):
    """Conditions for WAF and WAFRegional Rules"""

    negated: bool
    type: str
    data_id: str


class Rule(BaseModel):
    """Rule Model for WAF and WAFRegional"""

    arn: str
    id: str
    region: str
    name: str
    predicates: Optional[List[Predicate]] = Field(default_factory=list)
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class RuleGroup(BaseModel):
    """RuleGroup Model for WAF and WAFRegional"""

    arn: str
    id: str
    region: str
    name: str
    rules: List[Rule] = Field(default_factory=list)
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class WebAcl(BaseModel):
    """Web ACL Model for WAF and WAFRegional"""

    arn: str
    name: str
    id: str
    albs: List[str] = Field(default_factory=list)
    region: str
    rules: List[Rule] = Field(default_factory=list)
    rule_groups: List[RuleGroup] = Field(default_factory=list)
    logging_enabled: bool = Field(default=False)
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
