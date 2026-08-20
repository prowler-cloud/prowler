from datetime import datetime, timedelta
from typing import Optional

from botocore.client import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


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
        for trail in self.trails.values():
            for region, client in self.regional_clients.items():
                if trail.region == region and trail.name:
                    # Per trail, so that one unreadable trail neither aborts the scan of the
                    # remaining trails nor leaves them looking like they are not logging.
                    # `status_error` is what lets a check tell "could not read" apart from the
                    # False default of is_logging: a missing IsLogging raises here too.
                    try:
                        status = client.get_trail_status(Name=trail.arn)
                        trail.is_logging = status["IsLogging"]
                        if "LatestCloudWatchLogsDeliveryTime" in status:
                            trail.latest_cloudwatch_delivery_time = status[
                                "LatestCloudWatchLogsDeliveryTime"
                            ]
                    except Exception as error:
                        trail.status_error = error.__class__.__name__
                        logger.error(
                            f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

    def _get_event_selectors(self):
        logger.info("Cloudtrail - Getting event selector")
        for trail in self.trails.values():
            for region, client in self.regional_clients.items():
                if trail.region == region and trail.name:
                    # Per trail: an empty data_events list means "this trail selects no data
                    # events" to every check that reads it, so a failed read must be recorded
                    # rather than left to look like an answer.
                    try:
                        data_events = client.get_event_selectors(TrailName=trail.arn)
                    except Exception as error:
                        trail.event_selectors_error = error.__class__.__name__
                        logger.error(
                            f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        continue
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

    def _lookup_events_page(self, region, event_name, minutes):
        """Return ``(events, truncated, error)`` for a single lookup_events page.

        ``LookupEvents`` is a **per-region** API: even for a multi-region trail,
        events recorded in region X are only retrievable by calling
        ``LookupEvents`` against region X. This helper is therefore
        region-scoped; callers iterate over the audited regions themselves.

        - ``events``: list of raw event dicts (empty on no match or on error).
        - ``truncated``: True when the API returned a ``NextToken`` (coverage
          in this page is bounded; more events exist in the window).
        - ``error``: ``None`` on success; a short string when the call raised
          so callers can report incomplete visibility instead of interpreting
          an empty response as "no matches" (matches the fail-closed pattern).
        """
        logger.info("CloudTrail - Lookup Events (single-page)...")
        try:
            regional_client = self.regional_clients[region]
        except KeyError as error:
            logger.error(f"CloudTrail - unknown region '{region}': {error}")
            return [], False, f"unknown region '{region}'"
        try:
            response = regional_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                StartTime=datetime.now() - timedelta(minutes=minutes),
            )
            return response.get("Events") or [], bool(response.get("NextToken")), None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return [], False, error.__class__.__name__

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


def data_event_resource_types(event_selector: dict) -> tuple[set[str], set[str]]:
    """Split the resource types of one advanced event selector by coverage.

    eventCategory and resources.type are the only two fields that widen what a selector
    logs; every other supported field (eventName, readOnly, resources.ARN, eventSource,
    eventType, userIdentity.arn, sessionCredentialFromConsole) removes events from the
    selection, and how many it removes cannot be read back from the trail configuration.

    Args:
        event_selector: The raw ``AdvancedEventSelectors`` entry from
            ``GetEventSelectors``.

    Returns:
        ``(complete, narrowed)``: the ``resources.type`` values this selector logs
        every data event for, and those it logs only a filtered subset of. Both are
        empty when the selector is not a data event selector.
    """
    event_categories = set()
    resource_types = set()
    has_narrowing_field = False

    for field_selector in event_selector.get("FieldSelectors") or []:
        field = field_selector.get("Field")
        # eventCategory and resources.type can only use the Equals operator.
        values = field_selector.get("Equals") or []
        if field == "eventCategory":
            event_categories.update(values)
        elif field == "resources.type":
            resource_types.update(values)
        else:
            # Includes a field selector with no Field at all: an unrecognizable filter is a
            # filter whose effect on coverage is unknown, not one with no effect.
            has_narrowing_field = True

    if event_categories != {"Data"}:
        return set(), set()
    if has_narrowing_field:
        return set(), resource_types
    return resource_types, set()


def trail_data_event_coverage(
    trail: "Trail", resource_types: frozenset
) -> tuple[set[str], set[str]]:
    """Report how a trail's event selectors cover the given data event resource types.

    Args:
        trail: The trail whose event selectors have already been retrieved.
        resource_types: The ``resources.type`` values of interest.

    Basic (classic) event selectors need no special case: they carry ``DataResources``
    rather than ``FieldSelectors``, and their only supported resource types are
    AWS::DynamoDB::Table, AWS::Lambda::Function and AWS::S3::Object. Every other resource
    type requires an advanced event selector.

    Returns:
        ``(complete, narrowed)`` subsets of ``resource_types``. A type appearing in
        ``complete`` is never also reported as ``narrowed``.
    """
    complete = set()
    narrowed = set()
    for data_event in trail.data_events:
        selector_complete, selector_narrowed = data_event_resource_types(
            data_event.event_selector
        )
        complete |= selector_complete & resource_types
        narrowed |= selector_narrowed & resource_types
    return complete, narrowed - complete


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
    # Short exception names when GetTrailStatus / GetEventSelectors could not be read, so a
    # check can report an undetermined result instead of a verdict built on a default value.
    status_error: Optional[str] = None
    event_selectors_error: Optional[str] = None
