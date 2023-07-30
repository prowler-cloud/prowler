from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################### WAF
class WAF(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__("waf-regional", audit_info)
        self.web_acls = []
        self.__threading_call__(self.__list_web_acls__)
        self.__threading_call__(self.__list_resources_for_web_acl__)

    def __list_web_acls__(self, regional_client):
        logger.info("WAF - Listing Regional Web ACLs...")
        try:
            for waf in regional_client.list_web_acls()["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(waf["WebACLId"], self.audit_resources)
                ):
                    self.web_acls.append(
                        WebAcl(
                            name=waf["Name"],
                            id=waf["WebACLId"],
                            albs=[],
                            region=regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_resources_for_web_acl__(self, regional_client):
        logger.info("WAF - Describing resources...")
        try:
            for acl in self.web_acls:
                if acl.region == regional_client.region:
                    for resource in regional_client.list_resources_for_web_acl(
                        WebACLId=acl.id, ResourceType="APPLICATION_LOAD_BALANCER"
                    )["ResourceArns"]:
                        acl.albs.append(resource)

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class WebAcl(BaseModel):
    name: str
    id: str
    albs: list[str]
    region: str
