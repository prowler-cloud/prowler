from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class Bedrock(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.logging_configurations = {}
        self.__threading_call__(self._get_model_invocation_logging_configuration)

    def _get_model_invocation_logging_configuration(self, regional_client):
        logger.info("Bedrock - Getting Model Invocation Logging Configuration...")
        try:
            logging_config = (
                regional_client.get_model_invocation_logging_configuration().get(
                    "loggingConfig", {}
                )
            )
            if logging_config:
                self.logging_configurations[regional_client.region] = (
                    LoggingConfiguration(
                        cloudwatch_log_group=logging_config.get(
                            "cloudWatchConfig", {}
                        ).get("logGroupName"),
                        s3_bucket=logging_config.get("s3Config", {}).get("bucketName"),
                        enabled=True,
                    )
                )
            else:
                self.logging_configurations[regional_client.region] = (
                    LoggingConfiguration(enabled=False)
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class LoggingConfiguration(BaseModel):
    enabled: bool = False
    cloudwatch_log_group: Optional[str] = None
    s3_bucket: Optional[str] = None
