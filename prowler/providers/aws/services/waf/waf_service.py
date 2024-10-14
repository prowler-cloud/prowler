from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class WAF(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("waf-regional", provider)
        self.web_acls = {}
        self.__threading_call__(self._list_web_acls)
        self.__threading_call__(self._list_resources_for_web_acl)
        self.__threading_call__(self._get_web_acl, self.web_acls.values())

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


class Rule(BaseModel):
    id: str


class WebAcl(BaseModel):
    arn: str
    name: str
    id: str
    albs: list[str]
    region: str
    rules: list[Rule] = []
    rule_groups: list[Rule] = []
