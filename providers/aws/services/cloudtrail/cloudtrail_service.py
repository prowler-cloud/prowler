import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################### CLOUDTRAIL
class Cloudtrail:
    def __init__(self, audit_info):
        self.service = "cloudtrail"
        self.session = audit_info.audit_session
        self.account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.trail_regions = self.__get_trail_regions__()
        self.trails = []
        self.__threading_call__(self.__get_trails__)
        self.__get_trail_status__()

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __get_trails__(self, regional_client):
        logger.info("Cloudtrail - Getting trails...")
        try:
            describe_trails = regional_client.describe_trails()["trailList"]
            for trail in describe_trails:
                self.trails.append(
                    TrailDetails(
                        name=trail["Name"],
                        is_multiregion=trail["IsMultiRegionTrail"],
                        home_region=trail["HomeRegion"],
                        trail_arn=trail["TrailARN"],
                        region=regional_client.region,
                        is_logging=False,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __get_trail_status__(self):
        logger.info("Cloudtrail - Getting trail status")
        try:
            for trail in self.trails:
                for region, client in self.regional_clients.items():
                    if trail.region == region:
                        status = client.get_trail_status(Name=trail.trail_arn)
                        trail.is_logging = status["IsLogging"]

        except Exception as error:
            logger.error(f"{client.region} -- {error.__class__.__name__}: {error}")

    def __get_trail_regions__(self):
        regions = []
        for region in self.regional_clients.keys():
            regions.append(region)

        return regions


@dataclass
class TrailDetails:
    name: str
    is_multiregion: bool
    home_region: str
    trail_arn: str
    region: str
    is_logging: bool

    def __init__(
        self,
        name,
        is_multiregion,
        home_region,
        trail_arn,
        region,
        is_logging,
    ):
        self.name = name
        self.is_multiregion = is_multiregion
        self.home_region = home_region
        self.trail_arn = trail_arn
        self.region = region
        self.is_logging = is_logging

    def __getitem__(self, item):
        return getattr(self, item)
