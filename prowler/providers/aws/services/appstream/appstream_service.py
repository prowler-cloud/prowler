import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## AppStream
class AppStream:
    def __init__(self, audit_info):
        self.service = "appstream"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.fleets = []
        self.__threading_call__(self.__describe_fleets__)

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

    def __describe_fleets__(self, regional_client):
        logger.info("AppStream - Describing Fleets...")
        try:
            describe_fleets_paginator = regional_client.get_paginator("describe_fleets")
            for page in describe_fleets_paginator.paginate():
                for fleet in page["Fleets"]:
                    self.fleets.append(
                        Fleet(
                            arn=fleet["Arn"],
                            name=fleet["Name"],
                            max_user_duration_in_seconds=fleet[
                                "MaxUserDurationInSeconds"
                            ],
                            disconnect_timeout_in_seconds=fleet[
                                "DisconnectTimeoutInSeconds"
                            ],
                            idle_disconnect_timeout_in_seconds=fleet[
                                "IdleDisconnectTimeoutInSeconds"
                            ],
                            enable_default_internet_access=fleet[
                                "EnableDefaultInternetAccess"
                            ],
                            region=regional_client.region,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Fleet:
    arn: str
    name: str
    max_user_duration_in_seconds: int
    disconnect_timeout_in_seconds: int
    idle_disconnect_timeout_in_seconds: int
    enable_default_internet_access: bool

    def __init__(
        self,
        arn,
        name,
        max_user_duration_in_seconds,
        disconnect_timeout_in_seconds,
        idle_disconnect_timeout_in_seconds,
        enable_default_internet_access,
        region,
    ):
        self.arn = arn
        self.name = name
        self.max_user_duration_in_seconds = max_user_duration_in_seconds
        self.disconnect_timeout_in_seconds = disconnect_timeout_in_seconds
        self.idle_disconnect_timeout_in_seconds = idle_disconnect_timeout_in_seconds
        self.enable_default_internet_access = enable_default_internet_access
        self.region = region
