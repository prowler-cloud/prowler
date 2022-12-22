from dataclasses import dataclass
from enum import Enum

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## CloudFront
class CloudFront:
    def __init__(self, audit_info):
        self.service = "cloudfront"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.distributions = {}
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.distributions = self.__list_distributions__(self.client, self.region)
            self.distributions = self.__get_distribution_config__(
                self.client, self.distributions, self.region
            )

    def __get_session__(self):
        return self.session

    def __list_distributions__(self, client, region) -> dict:
        logger.info("CloudFront - Listing Distributions...")
        distributions = {}
        try:
            list_ditributions_paginator = client.get_paginator("list_distributions")
            for page in list_ditributions_paginator.paginate():
                if "Items" in page["DistributionList"]:
                    for item in page["DistributionList"]["Items"]:
                        distribution_id = item["Id"]
                        distribution_arn = item["ARN"]
                        origins = item["Origins"]["Items"]
                        distribution = Distribution(
                            arn=distribution_arn,
                            id=distribution_id,
                            origins=origins,
                            region=region,
                        )
                        distributions[distribution_id] = distribution

            return distributions

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
                default_chache_config = DefaultCacheConfigBehaviour(
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
                ].default_cache_config = default_chache_config

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return distributions


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


@dataclass
class Distribution:
    """Distribution holds a CloudFront Distribution with the required information to run the rela"""

    arn: str
    id: str
    region: str
    logging_enabled: bool
    default_cache_config: DefaultCacheConfigBehaviour
    geo_restriction_type: GeoRestrictionType
    origins: list
    web_acl_id: str

    def __init__(
        self,
        arn,
        id,
        region,
        origins,
        logging_enabled=False,
        default_cache_config=None,
        geo_restriction_type=None,
        web_acl_id="",
    ):
        self.arn = arn
        self.id = id
        self.region = region
        self.logging_enabled = logging_enabled
        self.default_cache_config = default_cache_config
        self.geo_restriction_type = geo_restriction_type
        self.origins = origins
        self.web_acl_id = web_acl_id
