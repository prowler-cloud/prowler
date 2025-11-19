"""Alibaba Cloud RDS Service"""

from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class DBInstance:
    """RDS DB Instance"""

    db_instance_id: str
    db_instance_name: str
    arn: str
    region: str
    engine: str = "MySQL"
    engine_version: str = "5.7"
    instance_type: str = ""
    status: str = "Running"
    public_access: bool = True  # Will trigger check
    encryption_enabled: bool = False  # Will trigger check
    backup_retention_period: int = 7
    backup_enabled: bool = True
    ssl_enabled: bool = False  # Will trigger check
    multi_az: bool = False  # Will trigger check
    auto_minor_version_upgrade: bool = False  # Will trigger check
    deletion_protection: bool = False  # Will trigger check
    audit_log_enabled: bool = False  # Will trigger check
    vpc_id: str = ""
    security_ips: list = None
    tags: dict = None

    def __post_init__(self):
        if self.security_ips is None:
            self.security_ips = ["0.0.0.0/0"]  # Insecure default
        if self.tags is None:
            self.tags = {}


class RDS(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("rds", provider)
        self.db_instances = {}
        logger.info("Collecting RDS instances...")
        self._describe_db_instances()
        logger.info(f"RDS service initialized - Instances: {len(self.db_instances)}")

    def _describe_db_instances(self):
        for region in self.regions:
            try:
                from alibabacloud_rds20140815 import models
                from alibabacloud_rds20140815.client import Client as RdsClient
                from alibabacloud_tea_openapi import models as openapi_models

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create RDS client
                client = RdsClient(config)

                # Describe DB instances
                request = models.DescribeDBInstancesRequest(
                    page_size=100, region_id=region
                )
                response = client.describe_dbinstances(request)

                # Process DB instances
                if response.body.items and response.body.items.dbinstance:
                    for db_data in response.body.items.dbinstance:
                        db_instance_id = db_data.dbinstance_id
                        arn = self.generate_resource_arn(
                            "dbinstance", db_instance_id, region
                        )

                        # Get detailed information
                        detail_request = models.DescribeDBInstanceAttributeRequest(
                            dbinstance_id=db_instance_id
                        )
                        detail_response = client.describe_dbinstance_attribute(
                            detail_request
                        )

                        if (
                            detail_response.body.items
                            and detail_response.body.items.dbinstance_attribute
                        ):
                            detail_data = (
                                detail_response.body.items.dbinstance_attribute[0]
                            )

                            # Check SSL status
                            ssl_enabled = False
                            try:
                                ssl_request = models.DescribeDBInstanceSSLRequest(
                                    dbinstance_id=db_instance_id
                                )
                                ssl_response = client.describe_dbinstance_ssl(
                                    ssl_request
                                )
                                ssl_enabled = (
                                    ssl_response.body.ssl_enabled
                                    if hasattr(ssl_response.body, "ssl_enabled")
                                    else False
                                )
                            except Exception:
                                pass

                            # Parse security IPs
                            security_ips = []
                            if detail_data.security_ip_list:
                                security_ips = detail_data.security_ip_list.split(",")

                            # Get tags
                            tags = {}
                            if (
                                hasattr(detail_data, "tags")
                                and detail_data.tags
                                and hasattr(detail_data.tags, "tag")
                            ):
                                for tag in detail_data.tags.tag:
                                    tags[tag.tag_key] = tag.tag_value

                            instance = DBInstance(
                                db_instance_id=db_instance_id,
                                db_instance_name=(
                                    detail_data.dbinstance_description
                                    if detail_data.dbinstance_description
                                    else db_instance_id
                                ),
                                arn=arn,
                                region=region,
                                engine=(
                                    detail_data.engine
                                    if detail_data.engine
                                    else "MySQL"
                                ),
                                engine_version=(
                                    detail_data.engine_version
                                    if detail_data.engine_version
                                    else ""
                                ),
                                instance_type=(
                                    detail_data.dbinstance_class
                                    if hasattr(detail_data, "dbinstance_class")
                                    else ""
                                ),
                                status=(
                                    detail_data.dbinstance_status
                                    if detail_data.dbinstance_status
                                    else "Unknown"
                                ),
                                public_access=(
                                    detail_data.connection_mode == "Performance"
                                    if hasattr(detail_data, "connection_mode")
                                    else False
                                ),
                                encryption_enabled=(
                                    detail_data.tdestatus == "Enabled"
                                    if hasattr(detail_data, "tdestatus")
                                    else False
                                ),
                                backup_retention_period=(
                                    detail_data.backup_retention_period
                                    if hasattr(detail_data, "backup_retention_period")
                                    else 7
                                ),
                                backup_enabled=(
                                    True
                                    if hasattr(detail_data, "backup_retention_period")
                                    and detail_data.backup_retention_period > 0
                                    else False
                                ),
                                ssl_enabled=ssl_enabled,
                                multi_az=(
                                    detail_data.category == "HighAvailability"
                                    if hasattr(detail_data, "category")
                                    else False
                                ),
                                auto_minor_version_upgrade=(
                                    detail_data.auto_upgrade_minor_version == "Auto"
                                    if hasattr(
                                        detail_data, "auto_upgrade_minor_version"
                                    )
                                    else False
                                ),
                                deletion_protection=(
                                    detail_data.deletion_protection
                                    if hasattr(detail_data, "deletion_protection")
                                    else False
                                ),
                                audit_log_enabled=False,  # Will be checked separately
                                vpc_id=(
                                    detail_data.vpc_id
                                    if hasattr(detail_data, "vpc_id")
                                    else ""
                                ),
                                security_ips=security_ips,
                                tags=tags,
                            )

                            self.db_instances[arn] = instance
                            logger.info(
                                f"Found RDS instance: {db_instance_id} in {region}"
                            )
                else:
                    logger.info(f"No RDS instances found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeDBInstances", region)
