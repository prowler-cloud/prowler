"""
Alibaba Cloud OSS Service

This module provides the service class for Alibaba Cloud Object Storage Service (OSS).
"""

from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class Bucket:
    """OSS Bucket"""

    name: str
    arn: str
    region: str
    creation_date: str = ""
    public_access: bool = True  # Will trigger check
    encryption_enabled: bool = False  # Will trigger check
    encryption_algorithm: str = ""
    versioning_enabled: bool = False  # Will trigger check
    logging_enabled: bool = False  # Will trigger check
    access_logging_target: str = ""
    lifecycle_rules: list = None
    cors_rules: list = None
    referer_config: dict = None
    website_config: dict = None
    transfer_acceleration: bool = False
    tags: dict = None

    def __post_init__(self):
        if self.lifecycle_rules is None:
            self.lifecycle_rules = []
        if self.cors_rules is None:
            self.cors_rules = []
        if self.referer_config is None:
            self.referer_config = {}
        if self.website_config is None:
            self.website_config = {}
        if self.tags is None:
            self.tags = {}


class OSS(AlibabaCloudService):
    """
    Alibaba Cloud OSS service class

    Handles collection of OSS resources including buckets, encryption settings,
    access controls, and logging configuration.
    """

    def __init__(self, provider):
        """Initialize OSS service"""
        super().__init__("oss", provider)

        self.buckets = {}

        logger.info("Collecting OSS buckets...")
        self._list_buckets()

        logger.info(f"OSS service initialized - Buckets: {len(self.buckets)}")

    def _list_buckets(self):
        """List all OSS buckets"""
        try:
            import oss2

            # OSS is global, we only need to list buckets once
            # Create auth object
            auth = oss2.Auth(
                self.provider.session.credentials.access_key_id,
                self.provider.session.credentials.access_key_secret,
            )

            # Use a default region endpoint to list all buckets
            service = oss2.Service(auth, "https://oss-cn-hangzhou.aliyuncs.com")

            # List all buckets
            bucket_list = service.list_buckets()

            for bucket_info in bucket_list.buckets:
                bucket_name = bucket_info.name
                region = bucket_info.location.replace(
                    "oss-", ""
                )  # Convert oss-cn-hangzhou to cn-hangzhou
                arn = self.generate_resource_arn("bucket", bucket_name, region)

                # Create bucket object to get detailed info
                bucket_obj = oss2.Bucket(
                    auth, f"https://{bucket_info.location}.aliyuncs.com", bucket_name
                )

                # Get bucket info
                try:
                    bucket_acl = bucket_obj.get_bucket_acl()
                    public_access = bucket_acl.acl in [
                        "public-read",
                        "public-read-write",
                    ]
                except Exception:
                    public_access = False

                # Get encryption
                encryption_enabled = False
                encryption_algorithm = ""
                try:
                    encryption_config = bucket_obj.get_bucket_encryption()
                    if encryption_config and encryption_config.sse_algorithm:
                        encryption_enabled = True
                        encryption_algorithm = encryption_config.sse_algorithm
                except Exception:
                    pass

                # Get versioning
                versioning_enabled = False
                try:
                    versioning = bucket_obj.get_bucket_versioning()
                    versioning_enabled = versioning.status == "Enabled"
                except Exception:
                    pass

                # Get logging
                logging_enabled = False
                access_logging_target = ""
                try:
                    logging_config = bucket_obj.get_bucket_logging()
                    if logging_config and logging_config.target_bucket:
                        logging_enabled = True
                        access_logging_target = logging_config.target_bucket
                except Exception:
                    pass

                # Get lifecycle rules
                lifecycle_rules = []
                try:
                    lifecycle = bucket_obj.get_bucket_lifecycle()
                    if lifecycle and lifecycle.rules:
                        for rule in lifecycle.rules:
                            lifecycle_rules.append(
                                {
                                    "id": rule.id,
                                    "status": rule.status,
                                }
                            )
                except Exception:
                    pass

                # Get CORS rules
                cors_rules = []
                try:
                    cors = bucket_obj.get_bucket_cors()
                    if cors and cors.rules:
                        for rule in cors.rules:
                            cors_rules.append(
                                {
                                    "AllowedOrigin": rule.allowed_origins,
                                    "AllowedMethod": rule.allowed_methods,
                                }
                            )
                except Exception:
                    pass

                # Get referer config
                referer_config = {}
                try:
                    referer = bucket_obj.get_bucket_referer()
                    if referer:
                        referer_config = {
                            "AllowEmpty": referer.allow_empty_referer,
                            "RefererList": referer.referers if referer.referers else [],
                        }
                except Exception:
                    pass

                # Get transfer acceleration
                transfer_acceleration = False
                try:
                    transfer_accel = bucket_obj.get_bucket_transfer_acceleration()
                    transfer_acceleration = (
                        transfer_accel.enabled if transfer_accel else False
                    )
                except Exception:
                    pass

                # Get tags
                tags = {}
                try:
                    tagging = bucket_obj.get_bucket_tagging()
                    if tagging and tagging.tag_set and tagging.tag_set.tagging_rule:
                        for tag_key, tag_value in tagging.tag_set.tagging_rule.items():
                            tags[tag_key] = tag_value
                except Exception:
                    pass

                bucket = Bucket(
                    name=bucket_name,
                    arn=arn,
                    region=region,
                    creation_date=bucket_info.creation_date,
                    public_access=public_access,
                    encryption_enabled=encryption_enabled,
                    encryption_algorithm=encryption_algorithm,
                    versioning_enabled=versioning_enabled,
                    logging_enabled=logging_enabled,
                    access_logging_target=access_logging_target,
                    lifecycle_rules=lifecycle_rules,
                    cors_rules=cors_rules,
                    referer_config=referer_config,
                    website_config={},
                    transfer_acceleration=transfer_acceleration,
                    tags=tags,
                )

                self.buckets[arn] = bucket
                logger.info(f"Found OSS bucket: {bucket_name} in {region}")

        except Exception as error:
            self._handle_api_error(error, "ListBuckets", "")
