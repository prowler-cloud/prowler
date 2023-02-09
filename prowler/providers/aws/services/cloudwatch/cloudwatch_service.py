import threading
from dataclasses import dataclass
from typing import Optional

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
                                alarm["AlarmArn"],
                                alarm["AlarmName"],
                                metric_name,
                                namespace,
                                regional_client.region,
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
        logger.info("CloudWatch Logs- Describing metric filters...")
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
                                filter["filterName"],
                                filter["metricTransformations"][0]["metricName"],
                                filter["filterPattern"],
                                filter["logGroupName"],
                                regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_log_groups__(self, regional_client):
        logger.info("CloudWatch Logs- Describing log groups...")
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
                                log_group["arn"],
                                log_group["logGroupName"],
                                retention_days,
                                kms,
                                regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class MetricAlarm:
    arn: str
    name: str
    metric: Optional[str]
    name_space: Optional[str]
    region: str

    def __init__(
        self,
        arn,
        name,
        metric,
        name_space,
        region,
    ):
        self.arn = arn
        self.name = name
        self.metric = metric
        self.name_space = name_space
        self.region = region


@dataclass
class MetricFilter:
    name: str
    metric: str
    pattern: str
    log_group: str
    region: str

    def __init__(
        self,
        name,
        metric,
        pattern,
        log_group,
        region,
    ):
        self.name = name
        self.metric = metric
        self.pattern = pattern
        self.log_group = log_group
        self.region = region


@dataclass
class LogGroup:
    arn: str
    name: str
    retention_days: int
    kms_id: str
    region: str

    def __init__(
        self,
        arn,
        name,
        retention_days,
        kms_id,
        region,
    ):
        self.arn = arn
        self.name = name
        self.retention_days = retention_days
        self.kms_id = kms_id
        self.region = region
