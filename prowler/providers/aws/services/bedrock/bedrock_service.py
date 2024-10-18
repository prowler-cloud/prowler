from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Bedrock(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.logging_configurations = {}
        self.guardrails = {}
        self.__threading_call__(self._get_model_invocation_logging_configuration)
        self.__threading_call__(self._list_guardrails)
        self.__threading_call__(self._get_guardrail, self.guardrails.values())
        self.__threading_call__(self._list_tags_for_resource, self.guardrails.values())

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

    def _list_guardrails(self, regional_client):
        logger.info("Bedrock - Listing Guardrails...")
        try:
            for guardrail in regional_client.list_guardrails().get("guardrails", []):
                if not self.audit_resources or (
                    is_resource_filtered(guardrail["arn"], self.audit_resources)
                ):
                    self.guardrails[guardrail["arn"]] = Guardrail(
                        id=guardrail["id"],
                        name=guardrail["name"],
                        arn=guardrail["arn"],
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_guardrail(self, guardrail):
        logger.info("Bedrock - Getting Guardrail...")
        try:
            guardrail_info = self.regional_clients[guardrail.region].get_guardrail(
                guardrailIdentifier=guardrail.id
            )
            guardrail.sensitive_information_filter = (
                "sensitiveInformationPolicy" in guardrail_info
            )
            for filter in guardrail_info.get("contentPolicy", {}).get("filters", []):
                if filter.get("type") == "PROMPT_ATTACK":
                    guardrail.prompt_attack_filter_strength = filter.get(
                        "inputStrength", "NONE"
                    )
        except Exception as error:
            logger.error(
                f"{guardrail.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, guardrail):
        logger.info("Bedrock - Listing Tags for Resource...")
        try:
            guardrail.tags = (
                self.regional_clients[guardrail.region]
                .list_tags_for_resource(resourceARN=guardrail.arn)
                .get("tags", [])
            )
        except Exception as error:
            logger.error(
                f"{guardrail.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class LoggingConfiguration(BaseModel):
    enabled: bool = False
    cloudwatch_log_group: Optional[str] = None
    s3_bucket: Optional[str] = None


class Guardrail(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    tags: Optional[list] = []
    sensitive_information_filter: bool = False
    prompt_attack_filter_strength: Optional[str]
