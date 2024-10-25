import json
from datetime import datetime, timezone
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
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
        super().__init__(__class__.__name__, provider)
        self.log_group_arn_template = f"arn:{self.audited_partition}:logs:{self.region}:{self.audited_account}:log-group"
        self.log_groups = {}
        self.__threading_call__(self._describe_log_groups)
        self.resource_policies = {}
        self.__threading_call__(self._describe_resource_policies)
        self.metric_filters = []
        self.__threading_call__(self._describe_metric_filters)
        if self.log_groups:
            if (
                "cloudwatch_log_group_no_secrets_in_logs"
                in provider.audit_metadata.expected_checks
            ):
                self.events_per_log_group_threshold = (
                    1000  # The threshold for number of events to return per log group.
                )
                self.__threading_call__(self._get_log_events)
            self.__threading_call__(
                self._list_tags_for_resource, self.log_groups.values()
            )

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
                        for lg in self.log_groups.values():
                            if lg.name == filter["logGroupName"]:
                                log_group = lg
                                break

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
                for log_group in page["logGroups"]:
                    if not self.audit_resources or (
                        is_resource_filtered(log_group["arn"], self.audit_resources)
                    ):
                        never_expire = False
                        kms = log_group.get("kmsKeyId")
                        retention_days = log_group.get("retentionInDays")
                        if not retention_days:
                            never_expire = True
                            retention_days = 9999
                        if self.log_groups is None:
                            self.log_groups = {}
                        self.log_groups[log_group["arn"]] = LogGroup(
                            arn=log_group["arn"],
                            name=log_group["logGroupName"],
                            retention_days=retention_days,
                            never_expire=never_expire,
                            kms_id=kms,
                            region=regional_client.region,
                        )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.log_groups:
                    self.log_groups = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_log_events(self, regional_client):
        regional_log_groups = [
            log_group
            for log_group in self.log_groups.values()
            if log_group.region == regional_client.region
        ]
        total_log_groups = len(regional_log_groups)
        logger.info(
            f"CloudWatch Logs - Retrieving log events for {total_log_groups} log groups in {regional_client.region}..."
        )
        try:
            for count, log_group in enumerate(regional_log_groups, start=1):
                events = regional_client.filter_log_events(
                    logGroupName=log_group.name,
                    limit=self.events_per_log_group_threshold,
                )["events"]
                for event in events:
                    if event["logStreamName"] not in log_group.log_streams:
                        log_group.log_streams[event["logStreamName"]] = []
                    log_group.log_streams[event["logStreamName"]].append(event)
                if count % 10 == 0:
                    logger.info(
                        f"CloudWatch Logs - Retrieved log events for {count}/{total_log_groups} log groups in {regional_client.region}..."
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        logger.info(
            f"CloudWatch Logs - Finished retrieving log events in {regional_client.region}..."
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
        logger.info(f"CloudWatch Logs - List Tags for Log Group {log_group.name}...")
        try:
            regional_client = self.regional_clients[log_group.region]
            response = regional_client.list_tags_for_resource(
                resourceArn=log_group.arn
            )["tags"]
            log_group.tags = [response]
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
    metric: Optional[str]
    name_space: Optional[str]
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
    log_group: Optional[LogGroup]
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
