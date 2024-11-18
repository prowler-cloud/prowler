from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Route53
class Route53(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider, global_service=True)
        self.hosted_zones = {}
        self.record_sets = []
        self._list_hosted_zones()
        self._list_query_logging_configs()
        self._list_tags_for_resource()
        self._list_resource_record_sets()

    def _list_hosted_zones(self):
        logger.info("Route53 - Listing Hosting Zones...")
        try:
            list_hosted_zones_paginator = self.client.get_paginator("list_hosted_zones")
            for page in list_hosted_zones_paginator.paginate():
                for hosted_zone in page["HostedZones"]:
                    hosted_zone_id = hosted_zone["Id"].replace("/hostedzone/", "")
                    arn = f"arn:{self.audited_partition}:route53:::hostedzone/{hosted_zone_id}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        hosted_zone_name = hosted_zone["Name"]
                        private_zone = hosted_zone["Config"]["PrivateZone"]

                        self.hosted_zones[hosted_zone_id] = HostedZone(
                            id=hosted_zone_id,
                            name=hosted_zone_name,
                            private_zone=private_zone,
                            arn=arn,
                            region=self.region,
                        )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_resource_record_sets(self):
        logger.info("Route53 - Listing Hosting Zones...")
        try:
            list_resource_record_sets_paginator = self.client.get_paginator(
                "list_resource_record_sets"
            )
            for zone_id in self.hosted_zones.keys():
                for page in list_resource_record_sets_paginator.paginate(
                    HostedZoneId=zone_id
                ):
                    for record in page["ResourceRecordSets"]:
                        self.record_sets.append(
                            RecordSet(
                                name=record["Name"],
                                type=record["Type"],
                                records=[
                                    resource_record["Value"]
                                    for resource_record in record.get(
                                        "ResourceRecords", []
                                    )
                                ],
                                is_alias=True if "AliasTarget" in record else False,
                                hosted_zone_id=zone_id,
                                region=self.region,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_query_logging_configs(self):
        logger.info("Route53 - Listing Query Logging Configs...")
        try:
            for hosted_zone in self.hosted_zones.values():
                list_query_logging_configs_paginator = self.client.get_paginator(
                    "list_query_logging_configs"
                )
                for page in list_query_logging_configs_paginator.paginate():
                    for logging_config in page["QueryLoggingConfigs"]:
                        self.hosted_zones[hosted_zone.id].logging_config = (
                            LoggingConfig(
                                cloudwatch_log_group_arn=logging_config[
                                    "CloudWatchLogsLogGroupArn"
                                ]
                            )
                        )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("Route53Domains - List Tags...")
        for hosted_zone in self.hosted_zones.values():
            try:
                response = self.client.list_tags_for_resource(
                    ResourceType="hostedzone", ResourceId=hosted_zone.id
                )["ResourceTagSet"]
                hosted_zone.tags = response.get("Tags")
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class LoggingConfig(BaseModel):
    cloudwatch_log_group_arn: str


class HostedZone(BaseModel):
    id: str
    arn: str
    name: str
    private_zone: bool
    logging_config: LoggingConfig = None
    region: str
    tags: Optional[list] = []


class RecordSet(BaseModel):
    name: str
    type: str
    is_alias: bool
    records: list = []
    hosted_zone_id: str
    region: str


################## Route53Domains
class Route53Domains(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.domains = {}
        if self.audited_partition == "aws":
            # Route53Domains is a global service that supports endpoints in multiple AWS Regions
            # but you must specify the US East (N. Virginia) Region to create, update, or otherwise work with domains.
            self.region = "us-east-1"
            self.client = self.session.client(self.service, self.region)
            self._list_domains()
            self._get_domain_detail()
            self._list_tags_for_domain()

    def _list_domains(self):
        logger.info("Route53Domains - Listing Domains...")
        try:
            list_domains_zones_paginator = self.client.get_paginator("list_domains")
            for page in list_domains_zones_paginator.paginate():
                for domain in page["Domains"]:
                    domain_name = domain["DomainName"]

                    self.domains[domain_name] = Domain(
                        name=domain_name,
                        arn=f"arn:{self.audited_partition}:route53:::domain/{domain_name}",
                        region=self.region,
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_domain_detail(self):
        logger.info("Route53Domains - Getting Domain Detail...")
        try:
            for domain in self.domains.values():
                domain_detail = self.client.get_domain_detail(DomainName=domain.name)
                self.domains[domain.name].admin_privacy = domain_detail["AdminPrivacy"]
                self.domains[domain.name].status_list = domain_detail.get("StatusList")

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_domain(self):
        logger.info("Route53Domains - List Tags...")
        for domain in self.domains.values():
            try:
                response = self.client.list_tags_for_domain(
                    DomainName=domain.name,
                )["TagList"]
                domain.tags = response
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Domain(BaseModel):
    name: str
    arn: str
    region: str
    admin_privacy: bool = False
    status_list: list[str] = None
    tags: Optional[list] = []
