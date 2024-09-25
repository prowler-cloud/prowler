from enum import Enum
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class CloudFront(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider, global_service=True)
        self.distributions = {}
        self._list_distributions(self.client, self.region)
        self._get_distribution_config(self.client, self.distributions, self.region)
        self._list_tags_for_resource(self.client, self.distributions, self.region)

    def _list_distributions(self, client, region) -> dict:
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
                            origin_groups = item.get("OriginGroups", {}).get(
                                "Items", []
                            )
                            origin_failover = all(
                                origin_group.get("Members", {}).get("Quantity", 0) >= 2
                                for origin_group in origin_groups
                            )
                            default_certificate = item["ViewerCertificate"][
                                "CloudFrontDefaultCertificate"
                            ]
                            certificate = item["ViewerCertificate"].get(
                                "Certificate", ""
                            )
                            ssl_support_method = SSLSupportMethod(
                                item["ViewerCertificate"].get(
                                    "SSLSupportMethod", "static-ip"
                                )
                            )
                            origins = []
                            for origin in item.get("Origins", {}).get("Items", []):
                                origins.append(
                                    Origin(
                                        id=origin["Id"],
                                        domain_name=origin["DomainName"],
                                        origin_protocol_policy=origin.get(
                                            "CustomOriginConfig", {}
                                        ).get("OriginProtocolPolicy", ""),
                                        origin_ssl_protocols=origin.get(
                                            "CustomOriginConfig", {}
                                        )
                                        .get("OriginSslProtocols", {})
                                        .get("Items", []),
                                        origin_access_control=origin.get(
                                            "OriginAccessControlId", ""
                                        ),
                                        s3_origin_config=origin.get(
                                            "S3OriginConfig", {}
                                        ),
                                    )
                                )
                            distribution = Distribution(
                                arn=distribution_arn,
                                id=distribution_id,
                                origins=origins,
                                region=region,
                                origin_failover=origin_failover,
                                ssl_support_method=ssl_support_method,
                                default_certificate=default_certificate,
                                certificate=certificate,
                            )
                            self.distributions[distribution_id] = distribution

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_distribution_config(self, client, distributions, region) -> dict:
        logger.info("CloudFront - Getting Distributions...")
        try:
            for distribution_id in distributions.keys():
                distribution_config = client.get_distribution_config(Id=distribution_id)

                # Global Config
                distributions[distribution_id].logging_enabled = distribution_config[
                    "DistributionConfig"
                ]["Logging"]["Enabled"]
                distributions[distribution_id].geo_restriction_type = (
                    GeoRestrictionType(
                        distribution_config["DistributionConfig"]["Restrictions"][
                            "GeoRestriction"
                        ]["RestrictionType"]
                    )
                )
                distributions[distribution_id].web_acl_id = distribution_config[
                    "DistributionConfig"
                ]["WebACLId"]
                distributions[distribution_id].default_root_object = (
                    distribution_config["DistributionConfig"].get(
                        "DefaultRootObject", ""
                    )
                )
                distributions[distribution_id].viewer_protocol_policy = (
                    distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("ViewerProtocolPolicy", "")
                )

                # Default Cache Config
                default_cache_config = DefaultCacheConfigBehaviour(
                    realtime_log_config_arn=distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("RealtimeLogConfigArn"),
                    viewer_protocol_policy=ViewerProtocolPolicy(
                        distribution_config["DistributionConfig"][
                            "DefaultCacheBehavior"
                        ].get("ViewerProtocolPolicy")
                    ),
                    field_level_encryption_id=distribution_config["DistributionConfig"][
                        "DefaultCacheBehavior"
                    ].get("FieldLevelEncryptionId"),
                )
                distributions[distribution_id].default_cache_config = (
                    default_cache_config
                )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, client, distributions, region):
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


class SSLSupportMethod(Enum):
    """Method types that viewer want to accept HTTPS requests from"""

    static_ip = "static-ip"
    sni_only = "sni-only"
    vip = "vip"


class DefaultCacheConfigBehaviour(BaseModel):
    realtime_log_config_arn: Optional[str]
    viewer_protocol_policy: ViewerProtocolPolicy
    field_level_encryption_id: str


class Origin(BaseModel):
    id: str
    domain_name: str
    origin_protocol_policy: str
    origin_ssl_protocols: list[str]
    origin_access_control: Optional[str]
    s3_origin_config: Optional[dict]


class Distribution(BaseModel):
    """Distribution holds a CloudFront Distribution resource"""

    arn: str
    id: str
    region: str
    logging_enabled: bool = False
    default_cache_config: Optional[DefaultCacheConfigBehaviour]
    geo_restriction_type: Optional[GeoRestrictionType]
    origins: list[Origin]
    web_acl_id: str = ""
    default_certificate: Optional[bool]
    default_root_object: Optional[str]
    viewer_protocol_policy: Optional[str]
    tags: Optional[list] = []
    origin_failover: Optional[bool]
    ssl_support_method: Optional[SSLSupportMethod]
    certificate: Optional[str]
