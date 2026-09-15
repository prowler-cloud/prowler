import json
import re
from datetime import datetime, timezone
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.resource_limit import (
    get_resource_scan_limit,
    limit_resources,
)
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

_QUERY_ID = re.compile(r"\b[a-z][A-Za-z0-9_]*\b")
_QUOTED_TEXT = re.compile(r"""(?:"[^"]*"|'[^']*')""")
_METRICS_CALL = re.compile(r"""\bMETRICS\(\s*(?:(["'])(.*?)\1)?\s*\)""", re.IGNORECASE)


def _watched_metric_ids(queries):
    queries_by_id = {query["Id"]: query for query in queries if query.get("Id")}
    metric_ids = {
        query_id for query_id, query in queries_by_id.items() if "MetricStat" in query
    }
    pending = [
        query_id
        for query_id, query in queries_by_id.items()
        if query.get("ReturnData", True)
    ]
    watched = set()
    visited = set()

    while pending:
        query_id = pending.pop()
        if query_id in visited:
            continue
        visited.add(query_id)
        query = queries_by_id[query_id]
        if "MetricStat" in query:
            watched.add(query_id)
            continue

        expression = query.get("Expression", "")
        for match in _METRICS_CALL.finditer(expression):
            needle = match.group(2)
            pending.extend(
                metric_id
                for metric_id in metric_ids
                if needle is None or needle in metric_id
            )

        expression = _QUOTED_TEXT.sub("", expression)
        pending.extend(set(_QUERY_ID.findall(expression)) & queries_by_id.keys())

    return watched


def _metric_reference(metric, account_id=None):
    namespace = metric.get("Namespace")
    name = metric.get("MetricName")
    if not namespace or not name:
        return None
    dimensions = tuple(
        sorted(
            (dimension["Name"], dimension["Value"])
            for dimension in metric.get("Dimensions", [])
        )
    )
    return namespace, name, dimensions, account_id


class CloudWatch(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.metric_alarms = []
        self.all_metric_alarms = []
        # True when DescribeAlarms was denied in at least one audited region,
        # so the alarm inventory may be incomplete.
        self.metric_alarms_unavailable = False
        self.metric_alarms_scanned_regions = set()
        self.metric_alarms_scan_errors = {}
        self.__threading_call__(self._describe_alarms)
        if (
            not self.metric_alarms
            and not self.metric_alarms_scanned_regions
            and "AccessDenied" in self.metric_alarms_scan_errors.values()
        ):
            self.metric_alarms = None
        if self.metric_alarms:
            self._list_tags_for_resource()

    def _describe_alarms(self, regional_client):
        logger.info("CloudWatch - Describing alarms...")
        try:
            describe_alarms_paginator = regional_client.get_paginator("describe_alarms")
            for page in describe_alarms_paginator.paginate():
                for alarm in page["MetricAlarms"]:
                    metric_name = alarm.get("MetricName")
                    namespace = alarm.get("Namespace")
                    namespaces = {namespace} if namespace else set()
                    metric_references = set()
                    direct_reference = _metric_reference(alarm)
                    if direct_reference:
                        metric_references.add(direct_reference)
                    queries = alarm.get("Metrics", [])
                    for query in queries:
                        metric = query.get("MetricStat", {}).get("Metric", {})
                        query_namespace = metric.get("Namespace")
                        if query_namespace:
                            namespaces.add(query_namespace)
                    watched_metric_ids = _watched_metric_ids(queries)
                    for query in queries:
                        if query.get("Id") not in watched_metric_ids:
                            continue
                        metric = query.get("MetricStat", {}).get("Metric", {})
                        reference = _metric_reference(metric, query.get("AccountId"))
                        if reference:
                            metric_references.add(reference)
                    metric_alarm = MetricAlarm(
                        arn=alarm["AlarmArn"],
                        name=alarm["AlarmName"],
                        metric=metric_name,
                        name_space=namespace,
                        namespaces=sorted(namespaces),
                        metric_references=[
                            MetricReference(
                                namespace=reference[0],
                                name=reference[1],
                                dimensions=dict(reference[2]),
                                account_id=reference[3],
                            )
                            for reference in sorted(
                                metric_references,
                                key=lambda item: (
                                    item[0],
                                    item[1],
                                    item[2],
                                    item[3] or "",
                                ),
                            )
                        ],
                        region=regional_client.region,
                        alarm_actions=alarm.get("AlarmActions", []),
                        actions_enabled=alarm.get("ActionsEnabled", False),
                    )
                    self.all_metric_alarms.append(metric_alarm)
                    if not self.audit_resources or (
                        is_resource_filtered(alarm["AlarmArn"], self.audit_resources)
                    ):
                        self.metric_alarms.append(metric_alarm)
        except ClientError as error:
            error_code = error.response.get("Error", {}).get(
                "Code", error.__class__.__name__
            )
            self.metric_alarms_unavailable = True
            self.metric_alarms_scan_errors[regional_client.region] = error_code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.metric_alarms_unavailable = True
            self.metric_alarms_scan_errors[regional_client.region] = (
                error.__class__.__name__
            )
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            self.metric_alarms_scanned_regions.add(regional_client.region)

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
        super().__init__(__class__.__name__, provider)
        self.log_group_arn_template = f"arn:{self.audited_partition}:logs:{self.region}:{self.audited_account}:log-group"
        # Log groups are listed first, then only the selected subset is enriched
        # and exposed for primary log group checks. Keep a complete lightweight
        # index for cross-service evidence lookups.
        self.all_log_groups = {}
        self.log_groups = {}
        # True when DescribeLogGroups was denied in at least one audited
        # region, so the log group inventory may be incomplete.
        self.log_groups_unavailable = False
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
        # True when DescribeMetricFilters was denied in at least one audited
        # region, so the metric filter inventory may be incomplete.
        self.metric_filters_unavailable = False
        self.__threading_call__(self._describe_metric_filters)
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
                                metric_namespace=filter["metricTransformations"][0].get(
                                    "metricNamespace"
                                ),
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
                self.metric_filters_unavailable = True
                if not self.metric_filters:
                    self.metric_filters = None
            else:
                self.metric_filters_unavailable = True
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            self.metric_filters_unavailable = True
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_log_groups(self, regional_client):
        """List the log groups in a region into the complete and the analysed indexes.

        A denied DescribeLogGroups sets both indexes to None, but only while nothing has been
        collected yet: that None is the state checks read as "inventory unknown", and it must stay
        distinguishable from an account that genuinely has no log groups. Any other failure leaves
        the indexes as they are, so a partial inventory reads as a smaller one.

        dataProtectionStatus and inheritedProperties are stored as reported. An absent
        dataProtectionStatus is the API saying the log group has never had a policy, and it is kept
        as None rather than a status string so a check can tell "never configured" from DISABLED.
        """
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
                            data_protection_status=log_group.get(
                                "dataProtectionStatus"
                            ),
                            inherited_properties=log_group.get(
                                "inheritedProperties", []
                            ),
                            region=regional_client.region,
                        )
                        self.all_log_groups[log_group_object.arn] = log_group_object
                        self.log_groups[log_group_object.arn] = log_group_object
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                self.log_groups_unavailable = True
                if not self.log_groups:
                    self.all_log_groups = None
                    self.log_groups = None
            else:
                self.log_groups_unavailable = True
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            self.log_groups_unavailable = True
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


class MetricReference(BaseModel):
    """Metric identity referenced by a CloudWatch alarm.

    Attributes:
        namespace: CloudWatch metric namespace.
        name: CloudWatch metric name.
        dimensions: Dimensions attached to the metric.
        account_id: Optional source account set on a metric query.
    """

    namespace: str
    name: str
    dimensions: dict[str, str] = Field(default_factory=dict)
    account_id: Optional[str] = None


class MetricAlarm(BaseModel):
    arn: str
    name: str
    metric: Optional[str] = None
    name_space: Optional[str] = None
    namespaces: list[str] = Field(default_factory=list)
    metric_references: list[MetricReference] = Field(default_factory=list)
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
    # None when the log group has never had a data protection policy, otherwise
    # ACTIVATED, DELETED, ARCHIVED or DISABLED.
    data_protection_status: Optional[str] = None
    # Properties inherited from account-level settings, e.g. ACCOUNT_DATA_PROTECTION.
    inherited_properties: list[str] = []
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
    metric_namespace: Optional[str] = None
    pattern: str
    log_group: Optional[LogGroup] = None
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
