from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Config(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.recorders = {}
        self.__threading_call__(self.describe_configuration_recorders)
        self.__threading_call__(
            self._describe_configuration_recorder_status, self.recorders.values()
        )

    def _get_recorder_arn_template(self, region):
        return f"arn:{self.audited_partition}:config:{region}:{self.audited_account}:recorder"

    def describe_configuration_recorders(self, regional_client):
        logger.info("Config - Listing Recorders...")
        try:
            recorders = regional_client.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )

            # No config recorders in region
            if not recorders:
                self.recorders[regional_client.region] = Recorder(
                    name=self.audited_account,
                    role_arn="",
                    region=regional_client.region,
                )
            else:
                for recorder in recorders:
                    if not self.audit_resources or (
                        is_resource_filtered(recorder["name"], self.audit_resources)
                    ):
                        self.recorders[recorder["name"]] = Recorder(
                            name=recorder["name"],
                            role_arn=recorder["roleARN"],
                            region=regional_client.region,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_configuration_recorder_status(self, recorder):
        logger.info("Config - Listing Recorders Status...")
        try:
            if recorder.name != self.audited_account:
                recorder_status = (
                    self.regional_clients[recorder.region]
                    .describe_configuration_recorder_status(
                        ConfigurationRecorderNames=[recorder.name]
                    )
                    .get("ConfigurationRecordersStatus", [])
                )

                if recorder_status:
                    recorder.recording = recorder_status[0].get("recording", False)
                    recorder.last_status = recorder_status[0].get(
                        "lastStatus", "Failure"
                    )

        except Exception as error:
            logger.error(
                f"{recorder.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Recorder(BaseModel):
    name: str
    role_arn: str
    recording: Optional[bool]
    last_status: Optional[str]
    region: str
