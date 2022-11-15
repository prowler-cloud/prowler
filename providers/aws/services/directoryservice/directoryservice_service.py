import threading
from datetime import datetime
from enum import Enum
from typing import Union

from pydantic import BaseModel

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## DirectoryService
class DirectoryService:
    def __init__(self, audit_info):
        self.service = "ds"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.directories = {}
        self.__threading_call__(self.__describe_directories__)
        self.__threading_call__(self.__list_log_subscriptions__)
        self.__threading_call__(self.__describe_event_topics__)
        self.__threading_call__(self.__list_certificates__)
        self.__threading_call__(self.__get_snapshot_limits__)

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

    def __describe_directories__(self, regional_client):
        logger.info("DirectoryService - Describing Directories...")
        try:
            describe_fleets_paginator = regional_client.get_paginator(
                "describe_directories"
            )
            for page in describe_fleets_paginator.paginate():
                for directory in page["DirectoryDescriptions"]:
                    directory_id = directory["DirectoryId"]
                    # Radius Configuration
                    radius_authentication_protocol = (
                        directory["RadiusSettings"]["AuthenticationProtocol"]
                        if "RadiusSettings" in directory
                        else None
                    )
                    radius_status = (
                        directory["RadiusStatus"]
                        if "RadiusStatus" in directory
                        else None
                    )

                    self.directories[directory_id] = Directory(
                        name=directory_id,
                        region=regional_client.region,
                        radius_settings=RadiusSettings(
                            authentication_protocol=radius_authentication_protocol,
                            status=radius_status,
                        ),
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_log_subscriptions__(self, regional_client):
        logger.info("DirectoryService - Listing Log Subscriptions...")
        try:
            for directory in self.directories:
                list_log_subscriptions_paginator = regional_client.get_paginator(
                    "list_log_subscriptions"
                )
                list_log_subscriptions_parameters = {"DirectoryId": directory}
                log_subscriptions = []
                for page in list_log_subscriptions_paginator.paginate(
                    **list_log_subscriptions_parameters
                ):
                    for log_subscription_info in page["LogSubscriptions"]:
                        log_subscriptions.append(
                            LogSubscriptions(
                                log_group_name=log_subscription_info["LogGroupName"],
                                created_date_time=log_subscription_info[
                                    "SubscriptionCreatedDateTime"
                                ],
                            )
                        )
                self.directories[directory].log_subscriptions = log_subscriptions
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_event_topics__(self, regional_client):
        logger.info("DirectoryService - Describing Event Topics...")
        try:
            for directory in self.directories:
                describe_event_topics_parameters = {"DirectoryId": directory}
                event_topics = []
                describe_event_topics = regional_client.describe_event_topics(
                    **describe_event_topics_parameters
                )
                for event_topic in describe_event_topics["EventTopics"]:
                    event_topics.append(
                        EventTopics(
                            topic_arn=event_topic["TopicArn"],
                            topic_name=event_topic["TopicName"],
                            status=event_topic["Status"],
                            created_date_time=event_topic["CreatedDateTime"],
                        )
                    )
                self.directories[directory].event_topics = event_topics
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_certificates__(self, regional_client):
        logger.info("DirectoryService - Listing Certificates...")
        try:
            for directory in self.directories:
                list_certificates_paginator = regional_client.get_paginator(
                    "list_certificates"
                )
                list_certificates_parameters = {"DirectoryId": directory}
                certificates = []
                for page in list_certificates_paginator.paginate(
                    **list_certificates_parameters
                ):
                    for certificate_info in page["CertificatesInfo"]:
                        certificates.append(
                            Certificate(
                                id=certificate_info["CertificateId"],
                                common_name=certificate_info["CommonName"],
                                state=certificate_info["State"],
                                expiry_date_time=certificate_info["ExpiryDateTime"],
                                type=certificate_info["Type"],
                            )
                        )
                self.directories[directory].certificates = certificates
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_snapshot_limits__(self, regional_client):
        logger.info("DirectoryService - Getting Snapshot Limits...")
        try:
            for directory in self.directories:

                get_snapshot_limits_parameters = {"DirectoryId": directory}
                snapshot_limit = regional_client.get_snapshot_limits(
                    **get_snapshot_limits_parameters
                )

                self.directories[directory].snapshots_limits = SnapshotLimit(
                    manual_snapshots_current_count=snapshot_limit["SnapshotLimits"][
                        "ManualSnapshotsCurrentCount"
                    ],
                    manual_snapshots_limit=snapshot_limit["SnapshotLimits"][
                        "ManualSnapshotsLimit"
                    ],
                    manual_snapshots_limit_reached=snapshot_limit["SnapshotLimits"][
                        "ManualSnapshotsLimitReached"
                    ],
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class SnapshotLimit(BaseModel):
    manual_snapshots_limit: int
    manual_snapshots_current_count: int
    manual_snapshots_limit_reached: bool


class LogSubscriptions(BaseModel):
    log_group_name: str
    created_date_time: datetime


class EventTopicStatus(Enum):
    Registered = "Registered"
    NotFound = "Topic not found"
    Failed = "Failed"
    Delete = "Deleted"


class EventTopics(BaseModel):
    topic_name: str
    topic_arn: str
    status: EventTopicStatus
    created_date_time: datetime


class CertificateType(Enum):
    ClientCertAuth = "ClientCertAuth"
    ClientLDAPS = "ClientLDAPS"


class CertificateState(Enum):
    Registering = "Registering"
    Registered = "Registered"
    RegisterFailed = "RegisterFailed"
    Deregistering = "Deregistering"
    Deregistered = "Deregistered"
    DeregisterFailed = "DeregisterFailed"


class Certificate(BaseModel):
    id: str
    common_name: str
    state: CertificateState
    expiry_date_time: datetime
    type: CertificateType


class AuthenticationProtocol(Enum):
    PAP = "PAP"
    CHAP = "CHAP"
    MS_CHAPv1 = "MS-CHAPv1"
    MS_CHAPv2 = "MS-CHAPv2"


class RadiusStatus(Enum):
    """Status of the RADIUS MFA server connection"""

    Creating = "Creating"
    Completed = "Completed"
    Failed = "Failed"


class RadiusSettings(BaseModel):
    authentication_protocol: Union[AuthenticationProtocol, None]
    status: Union[RadiusStatus, None]


class Directory(BaseModel):
    name: str
    log_subscriptions: list[LogSubscriptions] = []
    event_topics: list[EventTopics] = []
    certificates: list[Certificate] = []
    snapshots_limits: SnapshotLimit = None
    radius_settings: RadiusSettings = None
    region: str
