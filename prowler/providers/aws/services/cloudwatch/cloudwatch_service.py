import threading
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

    def __list_tags_for_resource__(self):
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

    def __list_tags_for_resource__(self):
        logger.info("CloudWatch Logs - List Tags...")
        try:
            for log_group in self.log_groups:
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
    tags: list = []


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
    tags: list = []
