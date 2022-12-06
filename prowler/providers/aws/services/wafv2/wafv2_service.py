import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################### WAFv2
class WAFv2:
    def __init__(self, audit_info):
        self.service = "wafv2"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.web_acls = []
        self.__threading_call__(self.__list_web_acls__)
        self.__threading_call__(self.__list_resources_for_web_acl__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_web_acls__(self, regional_client):
        logger.info("WAFv2 - Listing Regional Web ACLs...")
        try:
            for wafv2 in regional_client.list_web_acls(Scope="REGIONAL")["WebACLs"]:
                self.web_acls.append(
                    WebAclv2(
                        arn=wafv2["ARN"],
                        name=wafv2["Name"],
                        id=wafv2["Id"],
                        albs=[],
                        region=regional_client.region,
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_resources_for_web_acl__(self, regional_client):
        logger.info("WAFv2 - Describing resources...")
        try:
            for acl in self.web_acls:
                if acl.region == regional_client.region:
                    for resource in regional_client.list_resources_for_web_acl(
                        WebACLArn=acl.arn, ResourceType="APPLICATION_LOAD_BALANCER"
                    )["ResourceArns"]:
                        acl.albs.append(resource)

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class WebAclv2(BaseModel):
    arn: str
    name: str
    id: str
    albs: list[str]
    region: str
