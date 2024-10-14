from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class WAF(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("waf-regional", provider)
        self.web_acls = {}
        self.rules = {}
        self.__threading_call__(self._list_web_acls)
        self.__threading_call__(self._list_resources_for_web_acl)
        self.__threading_call__(self._get_web_acl, self.web_acls.values())
        self.__threading_call__(self._list_rules)
        self.__threading_call__(self._get_rule, self.rules.values())

    def _list_web_acls(self, regional_client):
        logger.info("WAF - Listing Regional Web ACLs...")
        try:
            for waf in regional_client.list_web_acls()["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(waf["WebACLId"], self.audit_resources)
                ):
                    arn = f"arn:aws:waf-regional:{regional_client.region}:{self.audited_account}:webacl/{waf['WebACLId']}"
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

    def _list_resources_for_web_acl(self, regional_client):
        logger.info("WAF - Describing resources...")
        try:
            for acl in self.web_acls.values():
                if acl.region == regional_client.region:
                    for resource in regional_client.list_resources_for_web_acl(
                        WebACLId=acl.id, ResourceType="APPLICATION_LOAD_BALANCER"
                    )["ResourceArns"]:
                        acl.albs.append(resource)

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_web_acl(self, acl):
        logger.info(f"WAF - Getting Web ACL {acl.name}...")
        try:
            get_web_acl = self.regional_clients[acl.region].get_web_acl(WebACLId=acl.id)
            for rule in get_web_acl.get("WebACL", {}).get("Rules", []):
                rule_id = rule.get("RuleGroupId", "")
                if rule.get("Type", "") == "GROUP":
                    acl.rule_groups.append(Rule(id=rule_id))
                else:
                    acl.rules.append(Rule(id=rule_id))
                logger.info(f"Rule: {rule['Name']} - Priority: {rule['Priority']}")
        except KeyError:
            logger.error(f"Web ACL {acl.name} not found in {acl.region}.")

    def _list_rules(self, regional_client):
        logger.info("WAF - Listing Regional Rules...")
        try:
            for rule in regional_client.list_rules().get("Rules", []):
                arn = f"arn:aws:waf-regional:{regional_client.region}:{self.audited_account}:rule/{rule['RuleId']}"
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
        logger.info(f"WAF - Getting Rule {rule.name}...")
        try:
            get_rule = self.regional_clients[rule.region].get_rule(RuleId=rule.id)
            for predicate in get_rule.get("Rule", {}).get("Predicates", []):
                rule.predicates.append(
                    Predicate(
                        negated=predicate.get("Negated", False),
                        data_id=predicate.get("DataId", ""),
                    )
                )
        except KeyError:
            logger.error(f"Rule {rule.name} not found in {rule.region}.")


class Predicate(BaseModel):
    negated: bool
    data_id: str


class Rule(BaseModel):
    arn: str
    id: str
    region: str
    name: str
    predicates: list[str] = []


class WebAcl(BaseModel):
    arn: str
    name: str
    id: str
    albs: list[str]
    region: str
    rules: list[Rule] = []
    rule_groups: list[Rule] = []
