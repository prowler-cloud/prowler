import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Config
class Config:
    def __init__(self, audit_info):
        self.service = "config"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.recorders = []
        self.__threading_call__(self.__describe_configuration_recorder_status__)

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

    def __describe_configuration_recorder_status__(self, regional_client):
        logger.info("Config - Listing Recorders...")
        try:
            recorders = regional_client.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"
            ]
            recorders_count = 0
            for recorder in recorders:
                if not self.audit_resources or (
                    is_resource_filtered(recorder["name"], self.audit_resources)
                ):
                    recorders_count += 1
                    if "lastStatus" in recorder:
                        self.recorders.append(
                            Recorder(
                                name=recorder["name"],
                                recording=recorder["recording"],
                                last_status=recorder["lastStatus"],
                                region=regional_client.region,
                            )
                        )
                    else:
                        self.recorders.append(
                            Recorder(
                                name=recorder["name"],
                                recording=recorder["recording"],
                                last_status=None,
                                region=regional_client.region,
                            )
                        )
            # No config recorders in region
            if recorders_count == 0:
                self.recorders.append(
                    Recorder(
                        name=self.audited_account,
                        recording=None,
                        last_status=None,
                        region=regional_client.region,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Recorder(BaseModel):
    name: str
    recording: Optional[bool]
    last_status: Optional[str]
    region: str
