from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Route53
class Route53:
    def __init__(self, audit_info):
        self.service = "route53"
        self.session = audit_info.audit_session
        self.audited_partition = audit_info.audited_partition
        self.hosted_zones = {}
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.__list_hosted_zones__()
            self.__list_query_logging_configs__()

    def __get_session__(self):
        return self.session

    def __list_hosted_zones__(self):
        logger.info("Route53 - Listing Hosting Zones...")
        try:
            list_hosted_zones_paginator = self.client.get_paginator("list_hosted_zones")
            for page in list_hosted_zones_paginator.paginate():
                for hosted_zone in page["HostedZones"]:
                    hosted_zone_id = hosted_zone["Id"].replace("/hostedzone/", "")
                    hosted_zone_name = hosted_zone["Name"]
                    private_zone = hosted_zone["Config"]["PrivateZone"]

                    self.hosted_zones[hosted_zone_id] = HostedZone(
                        id=hosted_zone_id,
                        name=hosted_zone_name,
                        private_zone=private_zone,
                        arn=f"arn:{self.audited_partition}:route53:::{hosted_zone_id}",
                        region=self.region,
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_query_logging_configs__(self):
        logger.info("Route53 - Listing Query Logging Configs...")
        try:
            for hosted_zone in self.hosted_zones.values():
                list_query_logging_configs_paginator = self.client.get_paginator(
                    "list_query_logging_configs"
                )
                for page in list_query_logging_configs_paginator.paginate():
                    for logging_config in page["QueryLoggingConfigs"]:
                        self.hosted_zones[
                            hosted_zone.id
                        ].logging_config = LoggingConfig(
                            cloudwatch_log_group_arn=logging_config[
                                "CloudWatchLogsLogGroupArn"
                            ]
                        )

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


################## Route53Domains
class Route53Domains:
    def __init__(self, audit_info):
        self.service = "route53domains"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.domains = {}
        if audit_info.audited_partition == "aws":
            # Route53Domains is a global service that supports endpoints in multiple AWS Regions
            # but you must specify the US East (N. Virginia) Region to create, update, or otherwise work with domains.
            self.region = "us-east-1"
            self.client = self.session.client(self.service, self.region)
            self.__list_domains__()
            self.__get_domain_detail__()

    def __get_session__(self):
        return self.session

    def __list_domains__(self):
        logger.info("Route53Domains - Listing Domains...")
        try:
            list_domains_zones_paginator = self.client.get_paginator("list_domains")
            for page in list_domains_zones_paginator.paginate():
                for domain in page["Domains"]:
                    domain_name = domain["DomainName"]

                    self.domains[domain_name] = Domain(
                        name=domain_name, region=self.region
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_domain_detail__(self):
        logger.info("Route53Domains - Getting Domain Detail...")
        try:
            for domain in self.domains.values():
                domain_detail = self.client.get_domain_detail(DomainName=domain.name)
                self.domains[domain.name].admin_privacy = domain_detail["AdminPrivacy"]
                self.domains[domain.name].status_list = domain_detail["StatusList"]

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Domain(BaseModel):
    name: str
    region: str
    admin_privacy: bool = False
    status_list: list[str] = None
