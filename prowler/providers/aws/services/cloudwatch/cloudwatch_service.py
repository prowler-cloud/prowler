import threading
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients, gen_regions_for_service

from prowler.providers.aws.lib.classes import Service
from prowler.providers.aws.lib.decorators.decorators import threading_regional, threading_global, timeit


################## CloudWatch
class CloudWatch(Service):
    def __init__(self, audit_info):
        super().__init__("cloudwatch", audit_info)
        # session is stored in
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.region = list(
            generate_regional_clients(
                self.service, audit_info, global_service=True
            ).keys()
        )[0]
        # self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.metric_alarms = []
        self.__describe_alarms__()
        # self.__threading_call__(self.__describe_alarms__)
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

    @threading_regional
    def __describe_alarms__(self):
        logger.info(f"CloudWatch - Describing alarms for region {self.regional_client.region}...")
        try:
            describe_alarms_paginator = self.regional_client.get_paginator("describe_alarms")
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
                        self.metric_alarms.append(
                            MetricAlarm(
                                arn=alarm["AlarmArn"],
                                name=alarm["AlarmName"],
                                metric=metric_name,
                                name_space=namespace,
                                region=self.regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @threading_global("metric_alarms")
    def __list_tags_for_resource__(self, metric_alarm):
        logger.info(f"CloudWatch - Listing Tags for metric alarm {metric_alarm.name}")
        try:
            # for metric_alarm in self.metric_alarms:
            regional_client = self.regional_clients[metric_alarm.region]
            response = regional_client.list_tags_for_resource(
                ResourceARN=metric_alarm.arn
            )["Tags"]
            metric_alarm.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


################## CloudWatch Logs
class Logs(Service):
    def __init__(self, audit_info):
        super().__init__("logs", audit_info)
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        # self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.metric_filters = []
        self.log_groups = []
        # self.__threading_call__(self.__describe_metric_filters__)
        self.__describe_metric_filters__()
        # self.__threading_call__(self.__describe_log_groups__)
        self.__describe_log_groups__()
        if (
            "cloudwatch_log_group_no_secrets_in_logs"
            in audit_info.audit_metadata.expected_checks
        ):
            self.events_per_log_group_threshold = (
                1000  # The threshold for number of events to return per log group.
            )
            self.__get_log_events__()
            # self.__threading_call__(self.__get_log_events__)
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

    @threading_regional
    def __describe_metric_filters__(self):
        logger.info(f"CloudWatch Logs - Describing metric filters for {self.regional_client.region}...")
        try:
            describe_metric_filters_paginator = self.regional_client.get_paginator(
                "describe_metric_filters"
            )
            for page in describe_metric_filters_paginator.paginate():
                for filter in page["metricFilters"]:
                    if not self.audit_resources or (
                        is_resource_filtered(filter["filterName"], self.audit_resources)
                    ):
                        self.metric_filters.append(
                            MetricFilter(
                                name=filter["filterName"],
                                metric=filter["metricTransformations"][0]["metricName"],
                                pattern=filter.get("filterPattern", ""),
                                log_group=filter["logGroupName"],
                                region=self.regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @threading_regional
    def __describe_log_groups__(self):
        logger.info(f"CloudWatch Logs - Describing log groups for {self.regional_client.region}...")
        try:
            describe_log_groups_paginator = self.regional_client.get_paginator(
                "describe_log_groups"
            )
            for page in describe_log_groups_paginator.paginate():
                for log_group in page["logGroups"]:
                    if not self.audit_resources or (
                        is_resource_filtered(log_group["arn"], self.audit_resources)
                    ):
                        kms = None
                        retention_days = 0
                        if "kmsKeyId" in log_group:
                            kms = log_group["kmsKeyId"]
                        if "retentionInDays" in log_group:
                            retention_days = log_group["retentionInDays"]
                        self.log_groups.append(
                            LogGroup(
                                arn=log_group["arn"],
                                name=log_group["logGroupName"],
                                retention_days=retention_days,
                                kms_id=kms,
                                region=self.regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @timeit
    @threading_global("log_groups")
    def __get_log_events__(self, log_group):
        logger.info(
            f"CloudWatch Logs - Retrieving log events for {log_group.name} log group in {log_group.region}..."
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
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        streams_collected = len(log_group.log_streams)
        events_collected = sum([len(v) for v in log_group.log_streams.values()])
        logger.info(
            f"CloudWatch Logs - Retrieved {events_collected} log events, across {streams_collected} log streams, for {log_group.name} log group..."
        )


    @threading_global("log_groups")
    def __list_tags_for_resource__(self,log_group):
        logger.info("CloudWatch Logs - List Tags...")
        try:
            regional_client = self.regional_clients[log_group.region]
            response = regional_client.list_tags_for_resource(
                resourceArn=log_group.arn.replace(":*", "")  # Remove the tailing :*
            )["tags"]
            log_group.tags = [response]
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


class MetricFilter(BaseModel):
    name: str
    metric: str
    pattern: str
    log_group: str
    region: str


class LogGroup(BaseModel):
    arn: str
    name: str
    retention_days: int
    kms_id: Optional[str]
    region: str
    log_streams: dict[
        str, list[str]
    ] = {}  # Log stream name as the key, array of events as the value
    tags: Optional[list] = []


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
