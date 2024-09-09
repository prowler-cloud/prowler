from datetime import datetime, timedelta
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################### CLOUDTRAIL
class Cloudtrail(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.trail_arn_template = f"arn:{self.audited_partition}:cloudtrail:{self.region}:{self.audited_account}:trail"
        self.trails = {}
        self.__threading_call__(self._get_trails)
        if self.trails:
            self._get_trail_status()
            self._get_insight_selectors()
            self._get_event_selectors()
            self._list_tags_for_resource()

    def _get_trail_arn_template(self, region):
        return (
            f"arn:{self.audited_partition}:cloudtrail:{region}:{self.audited_account}:trail"
            if region
            else f"arn:{self.audited_partition}:cloudtrail:{self.region}:{self.audited_account}:trail"
        )

    def _get_trails(self, regional_client):
        logger.info("Cloudtrail - Getting trails...")
        try:
            describe_trails = regional_client.describe_trails()["trailList"]
            trails_count = 0
            for trail in describe_trails:
                # If a multi region trail was already retrieved in another region
                if self.trails and trail["TrailARN"] in self.trails.keys():
                    continue

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
                    if self.trails is None:
                        self.trails = {}
                    self.trails[trail["TrailARN"]] = Trail(
                        name=trail["Name"],
                        is_multiregion=trail["IsMultiRegionTrail"],
                        home_region=trail["HomeRegion"],
                        arn=trail["TrailARN"],
                        region=regional_client.region,
                        is_logging=False,
                        log_file_validation_enabled=trail["LogFileValidationEnabled"],
                        latest_cloudwatch_delivery_time=None,
                        s3_bucket=trail["S3BucketName"],
                        kms_key=kms_key_id,
                        log_group_arn=log_group_arn,
                        data_events=[],
                        has_insight_selectors=trail.get("HasInsightSelectors"),
                    )
            if trails_count == 0:
                if self.trails is None:
                    self.trails = {}
                self.trails[self._get_trail_arn_template(regional_client.region)] = (
                    Trail(
                        region=regional_client.region,
                    )
                )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.trails:
                    self.trails = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_trail_status(self):
        logger.info("Cloudtrail - Getting trail status")
        try:
            for trail in self.trails.values():
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

    def _get_event_selectors(self):
        logger.info("Cloudtrail - Getting event selector")
        try:
            for trail in self.trails.values():
                for region, client in self.regional_clients.items():
                    if trail.region == region and trail.name:
                        data_events = client.get_event_selectors(TrailName=trail.arn)
                        # EventSelectors
                        if (
                            "EventSelectors" in data_events
                            and data_events["EventSelectors"]
                        ):
                            for event in data_events["EventSelectors"]:
                                event_selector = Event_Selector(
                                    is_advanced=False, event_selector=event
                                )
                                trail.data_events.append(event_selector)
                        # AdvancedEventSelectors
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

    def _get_insight_selectors(self):
        logger.info("Cloudtrail - Getting trail insight selectors...")

        try:
            for trail in self.trails.values():
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
                                logger.warning(
                                    f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                            elif (
                                error.response["Error"]["Code"]
                                == "UnsupportedOperationException"
                            ):
                                logger.warning(
                                    f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
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

    def _lookup_events(self, trail, event_name, minutes):
        logger.info("CloudTrail - Lookup Events...")
        try:
            regional_client = self.regional_clients[trail.region]
            response = regional_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                StartTime=datetime.now() - timedelta(minutes=minutes),
            )
            return response.get("Events")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("CloudTrail - List Tags...")
        try:
            for trail in self.trails.values():
                try:
                    # Check if trails are in this account and region
                    if (
                        trail.region == trail.home_region
                        and self.audited_account in trail.arn
                    ):
                        regional_client = self.regional_clients[trail.region]
                        response = regional_client.list_tags(
                            ResourceIdList=[trail.arn]
                        )["ResourceTagList"][0]
                        trail.tags = response.get("TagsList")
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
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
    # Region holds the region where the trail is audited
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
