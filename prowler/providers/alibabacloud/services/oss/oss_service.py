"""
Alibaba Cloud OSS Service

This module provides the service class for Alibaba Cloud Object Storage Service (OSS).
"""

from dataclasses import dataclass
from typing import Optional

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

        logger.info(
            f"OSS service initialized - Buckets: {len(self.buckets)}"
        )

    def _list_buckets(self):
        """List all OSS buckets"""
        for region in self.regions:
            try:
                # TODO: Implement actual SDK call
                # Placeholder: Create sample buckets for demonstration
                bucket_name = f"prowler-demo-bucket-{region}"
                arn = self.generate_resource_arn("bucket", bucket_name, region)

                bucket = Bucket(
                    name=bucket_name,
                    arn=arn,
                    region=region,
                    creation_date="2023-01-01",
                    public_access=True,  # Should be False
                    encryption_enabled=False,  # Should be True
                    encryption_algorithm="",  # Should be AES256 or KMS
                    versioning_enabled=False,  # Should be True
                    logging_enabled=False,  # Should be True
                    access_logging_target="",
                    lifecycle_rules=[],
                    cors_rules=[
                        {
                            "AllowedOrigin": ["*"],  # Too permissive
                            "AllowedMethod": ["GET", "POST"],
                        }
                    ],
                    referer_config={
                        "AllowEmpty": True,  # Should be False
                        "RefererList": []
                    },
                    website_config={},
                    transfer_acceleration=False,
                    tags={}
                )

                self.buckets[arn] = bucket

            except Exception as error:
                self._handle_api_error(error, "ListBuckets", region)
