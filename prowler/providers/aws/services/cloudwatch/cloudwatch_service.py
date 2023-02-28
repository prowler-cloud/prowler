import threading
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## CloudWatch
class CloudWatch:
    def __init__(self, audit_info):
        self.service = "cloudwatch"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.region = list(
            generate_regional_clients(
                self.service, audit_info, global_service=True
            ).keys()
        )[0]
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.metric_alarms = []
        self.__threading_call__(self.__describe_alarms__)

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

    def __describe_alarms__(self, regional_client):
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
                        self.metric_alarms.append(
                            MetricAlarm(
                                arn=alarm["AlarmArn"],
                                name=alarm["AlarmName"],
                                metric=metric_name,
                                name_space=namespace,
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


################## CloudWatch Logs
class Logs:
    def __init__(self, audit_info):
        self.service = "logs"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.metric_filters = []
        self.log_groups = []
        self.__threading_call__(self.__describe_metric_filters__)
        self.__threading_call__(self.__describe_log_groups__)
        if (
            "cloudwatch_log_group_no_secrets_in_logs"
            in audit_info.audit_metadata.expected_checks
        ):
            self.events_per_log_group_threshold = (
                1000  # The threshold for number of events to return per log group.
            )
            self.__threading_call__(self.__get_log_events__)

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

    def __describe_metric_filters__(self, regional_client):
        logger.info("CloudWatch Logs - Describing metric filters...")
        try:
            describe_metric_filters_paginator = regional_client.get_paginator(
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
                                pattern=filter["filterPattern"],
                                log_group=filter["logGroupName"],
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_log_groups__(self, regional_client):
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
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_log_events__(self, regional_client):
        regional_log_groups = [
            log_group
            for log_group in self.log_groups
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


class MetricAlarm(BaseModel):
    arn: str
    name: str
    metric: Optional[str]
    name_space: Optional[str]
    region: str


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
