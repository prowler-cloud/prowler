from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## CloudFront
class CloudFront:
    def __init__(self, audit_info):
        self.service = "cloudfront"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.distributions = {}
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.__list_distributions__(self.client, self.region)
            self.__get_distribution_config__(
                self.client, self.distributions, self.region
            )
            self.__list_tags_for_resource__(
                self.client, self.distributions, self.region
            )

    def __get_session__(self):
        return self.session

    def __list_distributions__(self, client, region) -> dict:
        logger.info("CloudFront - Listing Distributions...")
        try:
            list_ditributions_paginator = client.get_paginator("list_distributions")
            for page in list_ditributions_paginator.paginate():
                if "Items" in page["DistributionList"]:
                    for item in page["DistributionList"]["Items"]:
                        if not self.audit_resources or (
                            is_resource_filtered(item["ARN"], self.audit_resources)
                        ):
                            distribution_id = item["Id"]
                            distribution_arn = item["ARN"]
                            origins = item["Origins"]["Items"]
                            distribution = Distribution(
                                arn=distribution_arn,
                                id=distribution_id,
                                origins=origins,
                                region=region,
                            )
                            self.distributions[distribution_id] = distribution

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_distribution_config__(self, client, distributions, region) -> dict:
        logger.info("CloudFront - Getting Distributions...")
        try:
            for distribution_id in distributions.keys():
                distribution_config = client.get_distribution_config(Id=distribution_id)
                # Global Config
                distributions[distribution_id].logging_enabled = distribution_config[
                    "DistributionConfig"
                ]["Logging"]["Enabled"]
                distributions[
                    distribution_id
                ].geo_restriction_type = distribution_config["DistributionConfig"][
                    "Restrictions"
                ][
                    "GeoRestriction"
                ][
                    "RestrictionType"
                ]
                distributions[distribution_id].web_acl_id = distribution_config[
                    "DistributionConfig"
                ]["WebACLId"]

                # Default Cache Config
                default_cache_config = DefaultCacheConfigBehaviour(
                    realtime_log_config_arn=distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("RealtimeLogConfigArn"),
                    viewer_protocol_policy=distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("ViewerProtocolPolicy"),
                    field_level_encryption_id=distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("FieldLevelEncryptionId"),
                )
                distributions[
                    distribution_id
                ].default_cache_config = default_cache_config

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self, client, distributions, region):
        logger.info("CloudFront - List Tags...")
        try:
            for distribution in distributions.values():
                response = client.list_tags_for_resource(Resource=distribution.arn)[
                    "Tags"
                ]
                distribution.tags = response.get("Items")
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class OriginsSSLProtocols(Enum):
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"


class ViewerProtocolPolicy(Enum):
    """The protocol that viewers can use to access the files in the origin specified by TargetOriginId when a request matches the path pattern in PathPattern"""

    allow_all = "allow-all"
    redirect_to_https = "redirect-to-https"
    https_only = "https-only"


class GeoRestrictionType(Enum):
    """Method types that you want to use to restrict distribution of your content by country"""

    none = "none"
    blacklist = "blacklist"
    whitelist = "whitelist"


@dataclass
class DefaultCacheConfigBehaviour:
    realtime_log_config_arn: str
    viewer_protocol_policy: ViewerProtocolPolicy
    field_level_encryption_id: str


class Distribution(BaseModel):
    """Distribution holds a CloudFront Distribution with the required information to run the rela"""

    arn: str
    id: str
    region: str
    logging_enabled: bool = False
    default_cache_config: Optional[DefaultCacheConfigBehaviour]
    geo_restriction_type: Optional[GeoRestrictionType]
    origins: list
    web_acl_id: str = ""
    tags: Optional[list] = []
