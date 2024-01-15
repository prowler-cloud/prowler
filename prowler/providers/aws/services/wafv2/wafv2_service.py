from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################### WAFv2
class WAFv2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.web_acls = []
        self.__threading_call__(self.__list_web_acls__)
        self.__threading_call__(self.__list_resources_for_web_acl__)
        self.__threading_call__(self.__get_logging_configuration__)

    def __list_web_acls__(self, regional_client):
        logger.info("WAFv2 - Listing Regional Web ACLs...")
        try:
            for wafv2 in regional_client.list_web_acls(Scope="REGIONAL")["WebACLs"]:
                if not self.audit_resources or (
                    is_resource_filtered(wafv2["ARN"], self.audit_resources)
                ):
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

    def __get_logging_configuration__(self, regional_client):
        logger.info("WAFv2 - Get Logging Configuration...")
        for acl in self.web_acls:
            if acl.region == regional_client.region:
                try:
                    logging_enabled = regional_client.get_logging_configuration(
                        ResourceArn=acl.arn
                    )
                    acl.logging_enabled = bool(
                        logging_enabled["LoggingConfiguration"]["LogDestinationConfigs"]
                    )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def __list_resources_for_web_acl__(self, regional_client):
        logger.info("WAFv2 - Describing resources...")
        for acl in self.web_acls:
            if acl.region == regional_client.region:
                try:
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
    logging_enabled: bool = False
