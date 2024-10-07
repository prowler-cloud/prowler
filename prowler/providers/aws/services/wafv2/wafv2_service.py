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
        self.__threading_call__(self._list_web_acls)
        self.__threading_call__(
            self._list_resources_for_web_acl, self.web_acls.values()
        )
        self.__threading_call__(self._get_logging_configuration, self.web_acls.values())
        self.__threading_call__(self._list_tags, self.web_acls.values())

    def _list_web_acls(self, regional_client):
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
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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


class WebAclv2(BaseModel):
    arn: str
    name: str
    id: str
    albs: list[str]
    user_pools: list[str]
    region: str
    logging_enabled: bool = False
    tags: Optional[list]
