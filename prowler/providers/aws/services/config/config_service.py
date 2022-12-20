import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Config
class Config:
    def __init__(self, audit_info):
        self.service = "config"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
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
            if recorders:
                for recorder in recorders:
                    if "lastStatus" in recorder:
                        self.recorders.append(
                            Recorder(
                                recorder["name"],
                                recorder["recording"],
                                recorder["lastStatus"],
                                regional_client.region,
                            )
                        )
                    else:
                        self.recorders.append(
                            Recorder(
                                recorder["name"],
                                recorder["recording"],
                                None,
                                regional_client.region,
                            )
                        )
            # No config recorders in region
            else:
                self.recorders.append(
                    Recorder(
                        self.audited_account,
                        None,
                        None,
                        regional_client.region,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Recorder:
    name: str
    recording: bool
    last_status: str
    region: str

    def __init__(
        self,
        name,
        recording,
        last_status,
        region,
    ):
        self.name = name
        self.recording = recording
        self.last_status = last_status
        self.region = region
