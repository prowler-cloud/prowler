import json
from datetime import datetime, timezone
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.resource_limit import (
    get_resource_scan_limit,
    limit_resources,
)
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class CloudWatch(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.metric_alarms = []
        self.__threading_call__(self._describe_alarms)
        if self.metric_alarms:
            self._list_tags_for_resource()

    def _describe_alarms(self, regional_client):
        logger.info("CloudWatch - Describing alarms...")
        try:
            describe_alarms_paginator = regional_client.get_paginator("describe_alarms")
            for page in describe_alarms_paginator.paginate():
                for alarm in page["MetricAlarms"]:
                    if not self.audit_resources or (
                        is_resource_filtered(alarm["AlarmArn"], self.audit_resources)
                    ):
                        metric_name = None
                        if "MetricName" in alarm:
                            metric_name = alarm["MetricName"]
                        namespace = None
                        if "Namespace" in alarm:
                            namespace = alarm["Namespace"]
                        if self.metric_alarms is None:
                            self.metric_alarms = []
                        self.metric_alarms.append(
                            MetricAlarm(
                                arn=alarm["AlarmArn"],
                                name=alarm["AlarmName"],
                                metric=metric_name,
                                name_space=namespace,
                                region=regional_client.region,
                                alarm_actions=alarm.get("AlarmActions", []),
                                actions_enabled=alarm.get("ActionsEnabled", False),
                            )
                        )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.metric_alarms:
                    self.metric_alarms = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("CloudWatch - List Tags...")
        try:
            for metric_alarm in self.metric_alarms:
                regional_client = self.regional_clients[metric_alarm.region]
                response = regional_client.list_tags_for_resource(
                    ResourceARN=metric_alarm.arn
                )["Tags"]
                metric_alarm.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Logs(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        """Collect CloudWatch Logs inventory for the audited account.

        Args:
            provider: The AWS provider whose session and Regions to scan.

        Beyond the log groups and metric filters this class already collected, it now resolves
        vended-log delivery sources and deliveries -- but only when ``expected_checks`` names a check
        that reads them, following the same gating this class already applies to ``_get_log_events``.
        """
        super().__init__(__class__.__name__, provider)
        self.log_group_arn_template = f"arn:{self.audited_partition}:logs:{self.region}:{self.audited_account}:log-group"
        # Log groups are listed first, then only the selected subset is enriched
        # and exposed for primary log group checks. Keep a complete lightweight
        # index for cross-service evidence lookups.
        self.all_log_groups = {}
        self.log_groups = {}
        self._log_groups_hydrated = set()
        self.log_group_limit = get_resource_scan_limit(
            self.audit_config, "max_cloudwatch_log_groups"
        )
        # The threshold for number of events to return per log group.
        self.events_per_log_group_threshold = 1000
        self.__threading_call__(self._describe_log_groups)
        self._select_log_groups_for_analysis()
        self.resource_policies = {}
        self.__threading_call__(self._describe_resource_policies)
        self.metric_filters = []
        self.__threading_call__(self._describe_metric_filters)
        # Vended-log delivery inventory. Only collected when a check that reads
        # it is in scope, following the _get_log_events precedent below, so the
        # two extra paginated calls per Region are not paid by every audit.
        self.delivery_sources = {}
        self.deliveries = {}
        # These two CheckIDs are load-bearing STRINGS, not documentation: if either stops matching a
        # real check, the delivery inventory is silently not collected and the check that reads it
        # degrades with nothing failing anywhere. They moved with AgentCore into its own service
        # directory, so the prefix here is bedrockagentcore_.
        if {
            "bedrockagentcore_gateway_application_logs_enabled",
            "bedrockagentcore_memory_application_logs_enabled",
        }.intersection(provider.audit_metadata.expected_checks):
            self.__threading_call__(self._describe_delivery_sources)
            self.__threading_call__(self._describe_deliveries)
        if self.log_groups:
            if (
                "cloudwatch_log_group_no_secrets_in_logs"
                in provider.audit_metadata.expected_checks
            ):
                self.__threading_call__(self._get_log_events, self.log_groups.values())
            self.__threading_call__(
                self._list_tags_for_resource, self.log_groups.values()
            )

    def _select_log_groups_for_analysis(self):
        """Select the newest log groups for bounded analysis."""
        if not self.log_groups:
            return
        self.log_groups = {
            log_group.arn: log_group
            for log_group in limit_resources(
                sorted(
                    self.log_groups.values(),
                    key=lambda lg: lg.creation_time or 0,
                    reverse=True,
                ),
                self.log_group_limit,
            )
        }

    def _describe_metric_filters(self, regional_client):
        logger.info("CloudWatch Logs - Describing metric filters...")
        try:
            describe_metric_filters_paginator = regional_client.get_paginator(
                "describe_metric_filters"
            )
            for page in describe_metric_filters_paginator.paginate():
                for filter in page["metricFilters"]:
                    arn = f"arn:{self.audited_partition}:logs:{regional_client.region}:{self.audited_account}:metric-filter/{filter['filterName']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        if self.metric_filters is None:
                            self.metric_filters = []

                        log_group = None
                        for lg in (self.all_log_groups or {}).values():
                            if (
                                lg.name == filter["logGroupName"]
                                and lg.region == regional_client.region
                            ):
                                log_group = lg
                                break

                        if (
                            log_group
                            and log_group.arn in (self.log_groups or {})
                            and log_group.arn not in self._log_groups_hydrated
                        ):
                            self._list_tags_for_resource(log_group)

                        self.metric_filters.append(
                            MetricFilter(
                                arn=arn,
                                name=filter["filterName"],
                                metric=filter["metricTransformations"][0]["metricName"],
                                pattern=filter.get("filterPattern", ""),
                                log_group=log_group,
                                region=regional_client.region,
                            )
                        )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.metric_filters:
                    self.metric_filters = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_log_groups(self, regional_client):
        logger.info("CloudWatch Logs - Describing log groups...")
        try:
            describe_log_groups_paginator = regional_client.get_paginator(
                "describe_log_groups"
            )
            for page in describe_log_groups_paginator.paginate():
                for log_group in page.get("logGroups", []):
                    if not self.audit_resources or is_resource_filtered(
                        log_group["arn"], self.audit_resources
                    ):
                        never_expire = False
                        kms = log_group.get("kmsKeyId")
                        retention_days = log_group.get("retentionInDays")
                        if not retention_days:
                            never_expire = True
                            retention_days = 9999
                        if self.log_groups is None:
                            self.log_groups = {}
                        if self.all_log_groups is None:
                            self.all_log_groups = {}
                        log_group_object = LogGroup(
                            arn=log_group["arn"],
                            name=log_group["logGroupName"],
                            retention_days=retention_days,
                            never_expire=never_expire,
                            kms_id=kms,
                            creation_time=log_group.get("creationTime"),
                            region=regional_client.region,
                        )
                        self.all_log_groups[log_group_object.arn] = log_group_object
                        self.log_groups[log_group_object.arn] = log_group_object
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.log_groups:
                    self.all_log_groups = None
                    self.log_groups = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_log_events(self, log_group):
        """Retrieve recent log events for a selected log group.

        Args:
            log_group: Log group selected for bounded analysis.
        """
        logger.info(
            f"CloudWatch Logs - Retrieving log events for log group {log_group.name}..."
        )
        try:
            regional_client = self.regional_clients[log_group.region]
            events = regional_client.filter_log_events(
                logGroupName=log_group.name,
                limit=self.events_per_log_group_threshold,
            )["events"]
            for event in events:
                if event["logStreamName"] not in log_group.log_streams:
                    log_group.log_streams[event["logStreamName"]] = []
                log_group.log_streams[event["logStreamName"]].append(event)
        except Exception as error:
            logger.error(
                f"{log_group.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_resource_policies(self, regional_client):
        logger.info("CloudWatch Logs - Describing resource policies...")
        try:
            describe_resource_policies_paginator = regional_client.get_paginator(
                "describe_resource_policies"
            )
            if regional_client.region not in self.resource_policies:
                self.resource_policies[regional_client.region] = []
            for page in describe_resource_policies_paginator.paginate():
                for policy in page["resourcePolicies"]:
                    self.resource_policies[regional_client.region].append(
                        ResourcePolicy(
                            name=policy["policyName"],
                            policy=json.loads(policy["policyDocument"]),
                            region=regional_client.region,
                        )
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                self.resource_policies[regional_client.region] = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_delivery_sources(self, regional_client):
        """List the vended-log delivery sources registered in a Region.

        A delivery source names the resource that emits logs and the log type it
        emits. It is only half of the configuration: a source with no delivery
        attached delivers nothing.

        Args:
            regional_client: CloudWatch Logs client for the Region to scan.
        """
        logger.info("CloudWatch Logs - Describing delivery sources...")
        try:
            paginator = regional_client.get_paginator("describe_delivery_sources")
            sources = []
            for page in paginator.paginate():
                for source in page.get("deliverySources", []):
                    sources.append(
                        DeliverySource(
                            name=source.get("name", ""),
                            arn=source.get("arn", ""),
                            # Every member of DeliverySource is optional, so a
                            # missing resourceArns must become an empty list
                            # rather than propagate None into the ARN match.
                            resource_arns=source.get("resourceArns") or [],
                            service=source.get("service"),
                            log_type=source.get("logType"),
                            region=regional_client.region,
                        )
                    )
            self.delivery_sources[regional_client.region] = sources
        except Exception as error:
            # None means "unknown", not "none configured", following the
            # _describe_resource_policies sentinel above. Callers must not read
            # an unreadable inventory as a disabled one.
            self.delivery_sources[regional_client.region] = None
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_deliveries(self, regional_client):
        """List the vended-log deliveries configured in a Region.

        A delivery is the link that makes a source actually emit to a
        destination, so it is the object that proves logging is on.

        Args:
            regional_client: CloudWatch Logs client for the Region to scan.
        """
        logger.info("CloudWatch Logs - Describing deliveries...")
        try:
            paginator = regional_client.get_paginator("describe_deliveries")
            deliveries = []
            for page in paginator.paginate():
                for delivery in page.get("deliveries", []):
                    deliveries.append(
                        Delivery(
                            id=delivery.get("id", ""),
                            arn=delivery.get("arn", ""),
                            delivery_source_name=delivery.get("deliverySourceName"),
                            delivery_destination_arn=delivery.get(
                                "deliveryDestinationArn"
                            ),
                            delivery_destination_type=delivery.get(
                                "deliveryDestinationType"
                            ),
                            region=regional_client.region,
                        )
                    )
            self.deliveries[regional_client.region] = deliveries
        except Exception as error:
            self.deliveries[regional_client.region] = None
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, log_group):
        """Hydrate tags for a selected log group once.

        Args:
            log_group: Log group selected for tag hydration.
        """
        if log_group.arn in self._log_groups_hydrated:
            return
        logger.info(f"CloudWatch Logs - List Tags for Log Group {log_group.name}...")
        try:
            regional_client = self.regional_clients[log_group.region]
            response = regional_client.list_tags_for_resource(
                resourceArn=log_group.arn
            )["tags"]
            log_group.tags = [response]
            self._log_groups_hydrated.add(log_group.arn)
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class MetricAlarm(BaseModel):
    arn: str
    name: str
    metric: Optional[str] = None
    name_space: Optional[str] = None
    region: str
    tags: Optional[list] = []
    alarm_actions: list
    actions_enabled: bool


class LogGroup(BaseModel):
    arn: str
    name: str
    retention_days: int
    never_expire: bool
    kms_id: Optional[str]
    creation_time: Optional[int] = None
    region: str
    log_streams: dict[str, list[str]] = (
        {}
    )  # Log stream name as the key, array of events as the value
    tags: Optional[list] = []


class ResourcePolicy(BaseModel):
    name: str
    policy: dict
    region: str


class MetricFilter(BaseModel):
    arn: str
    name: str
    metric: str
    pattern: str
    log_group: Optional[LogGroup] = None
    region: str


class DeliverySource(BaseModel):
    """A vended-log delivery source: the resource emitting logs and its log type."""

    name: str
    arn: str
    # ARNs of the resources that emit through this source. This is the only
    # field that ties a source to a specific resource, so it is the join key.
    resource_arns: list = []
    service: Optional[str] = None
    log_type: Optional[str] = None
    region: str


class Delivery(BaseModel):
    """A vended-log delivery linking a delivery source to a destination."""

    id: str
    arn: str
    # Matches DeliverySource.name; there is no source ARN on the delivery.
    delivery_source_name: Optional[str] = None
    delivery_destination_arn: Optional[str] = None
    delivery_destination_type: Optional[str] = None
    region: str


def convert_to_cloudwatch_timestamp_format(epoch_time):
    date_time = datetime.fromtimestamp(
        epoch_time / 1000, datetime.now(timezone.utc).astimezone().tzinfo
    )
    datetime_str = date_time.strftime(
        "%Y-%m-%dT%H:%M:%S.!%f!%z"
    )  # use exclamation marks as placeholders to convert datetime str to cloudwatch timestamp str
    datetime_parts = datetime_str.split("!")
    return (
        datetime_parts[0]
        + datetime_parts[1][:-3]
        + datetime_parts[2][:-2]
        + ":"
        + datetime_parts[2][-2:]
    )  # Removes the microseconds, and places a ':' character in the timezone offset
