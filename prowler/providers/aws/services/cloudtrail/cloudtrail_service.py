import threading
from datetime import datetime
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################### CLOUDTRAIL
class Cloudtrail(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)
        self.trails = []
        self.__threading_call__(self.__get_trails__)
        self.__get_trail_status__()
        self.__get_insight_selectors__()
        self.__get_event_selectors__()
        self.__list_tags_for_resource__()

    def __get_session__(self):
        return self.session

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
            trails_count = 0
            for trail in describe_trails:
                if not self.audit_resources or (
                    is_resource_filtered(trail["TrailARN"], self.audit_resources)
                ):
                    trails_count += 1
                    kms_key_id = None
                    log_group_arn = None
                    if "KmsKeyId" in trail:
                        kms_key_id = trail["KmsKeyId"]
                    if "CloudWatchLogsLogGroupArn" in trail:
                        log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                    self.trails.append(
                        Trail(
                            name=trail["Name"],
                            is_multiregion=trail["IsMultiRegionTrail"],
                            home_region=trail["HomeRegion"],
                            arn=trail["TrailARN"],
                            region=regional_client.region,
                            is_logging=False,
                            log_file_validation_enabled=trail[
                                "LogFileValidationEnabled"
                            ],
                            latest_cloudwatch_delivery_time=None,
                            s3_bucket=trail["S3BucketName"],
                            kms_key=kms_key_id,
                            log_group_arn=log_group_arn,
                            data_events=[],
                            has_insight_selectors=trail["HasInsightSelectors"],
                        )
                    )
            if trails_count == 0:
                self.trails.append(
                    Trail(
                        region=regional_client.region,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_trail_status__(self):
        logger.info("Cloudtrail - Getting trail status")
        try:
            for trail in self.trails:
                for region, client in self.regional_clients.items():
                    if trail.region == region and trail.name:
                        status = client.get_trail_status(Name=trail.arn)
                        trail.is_logging = status["IsLogging"]
                        if "LatestCloudWatchLogsDeliveryTime" in status:
                            trail.latest_cloudwatch_delivery_time = status[
                                "LatestCloudWatchLogsDeliveryTime"
                            ]

        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_event_selectors__(self):
        logger.info("Cloudtrail - Getting event selector")
        try:
            for trail in self.trails:
                for region, client in self.regional_clients.items():
                    if trail.region == region and trail.name:
                        data_events = client.get_event_selectors(TrailName=trail.arn)
                        # check if key exists and array associated to that key is not empty
                        if (
                            "EventSelectors" in data_events
                            and data_events["EventSelectors"]
                        ):
                            for event in data_events["EventSelectors"]:
                                event_selector = Event_Selector(
                                    is_advanced=False, event_selector=event
                                )
                                trail.data_events.append(event_selector)
                        # check if key exists and array associated to that key is not empty
                        elif (
                            "AdvancedEventSelectors" in data_events
                            and data_events["AdvancedEventSelectors"]
                        ):
                            for event in data_events["AdvancedEventSelectors"]:
                                event_selector = Event_Selector(
                                    is_advanced=True, event_selector=event
                                )
                                trail.data_events.append(event_selector)

        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_insight_selectors__(self):
        logger.info("Cloudtrail - Getting trail insihgt selectors...")

        try:
            for trail in self.trails:
                for region, client in self.regional_clients.items():
                    if trail.region == region and trail.name:
                        insight_selectors = None
                        trail.has_insight_selectors = None
                        try:
                            client_insight_selectors = client.get_insight_selectors(
                                TrailName=trail.arn
                            )
                            insight_selectors = client_insight_selectors.get(
                                "InsightSelectors"
                            )
                        except ClientError as error:
                            if (
                                error.response["Error"]["Code"]
                                == "InsightNotEnabledException"
                            ):
                                continue
                            else:
                                logger.error(
                                    f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                        except Exception as error:
                            logger.error(
                                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                            continue
                        if insight_selectors:
                            trail.has_insight_selectors = insight_selectors[0].get(
                                "InsightType"
                            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("CloudTrail - List Tags...")
        try:
            for trail in self.trails:
                # Check if trails are in this account and region
                if (
                    trail.region == trail.home_region
                    and self.audited_account in trail.arn
                ):
                    regional_client = self.regional_clients[trail.region]
                    response = regional_client.list_tags(ResourceIdList=[trail.arn])[
                        "ResourceTagList"
                    ][0]
                    trail.tags = response.get("TagsList")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Event_Selector(BaseModel):
    is_advanced: bool
    event_selector: dict


class Trail(BaseModel):
    name: str = None
    is_multiregion: bool = None
    home_region: str = None
    arn: str = None
    region: str
    is_logging: bool = None
    log_file_validation_enabled: bool = None
    latest_cloudwatch_delivery_time: datetime = None
    s3_bucket: str = None
    kms_key: str = None
    log_group_arn: str = None
    data_events: list[Event_Selector] = []
    tags: Optional[list] = []
    has_insight_selectors: str = None
