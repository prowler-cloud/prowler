from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## AppStream
class AppStream(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.fleets = []
        self.__threading_call__(self.__describe_fleets__)
        self.__threading_call__(self.__list_tags_for_resource__, self.fleets)

    def __describe_fleets__(self, regional_client):
        logger.info("AppStream - Describing Fleets...")
        try:
            describe_fleets_paginator = regional_client.get_paginator("describe_fleets")
            for page in describe_fleets_paginator.paginate():
                for fleet in page["Fleets"]:
                    if not self.audit_resources or (
                        is_resource_filtered(fleet["Arn"], self.audit_resources)
                    ):
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
                                idle_disconnect_timeout_in_seconds=fleet.get(
                                    "IdleDisconnectTimeoutInSeconds"
                                ),
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

    def __list_tags_for_resource__(self, fleet):
        try:
            regional_client = self.regional_clients[fleet.region]
            response = regional_client.list_tags_for_resource(ResourceArn=fleet.arn)[
                "Tags"
            ]
            fleet.tags = [response]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Fleet(BaseModel):
    arn: str
    name: str
    max_user_duration_in_seconds: int
    disconnect_timeout_in_seconds: int
    idle_disconnect_timeout_in_seconds: Optional[int]
    enable_default_internet_access: bool
    region: str
    tags: Optional[list] = []
