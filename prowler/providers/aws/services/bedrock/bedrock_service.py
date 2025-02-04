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

    def _get_model_invocation_logging_arn_template(self, region):
        return (
            f"arn:{self.audited_partition}:bedrock:{region}:{self.audited_account}:model-invocation-logging"
            if region
            else f"arn:{self.audited_partition}:bedrock:{self.region}:{self.audited_account}:model-invocation-logging"
        )

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


class BedrockAgent(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("bedrock-agent", provider)
        self.agents = {}
        self.__threading_call__(self._list_agents)
        self.__threading_call__(self._list_tags_for_resource, self.agents.values())

    def _list_agents(self, regional_client):
        logger.info("Bedrock Agent - Listing Agents...")
        try:
            for agent in regional_client.list_agents().get("agentSummaries", []):
                agent_arn = f"arn:aws:bedrock:{regional_client.region}:{self.audited_account}:agent/{agent['agentId']}"
                if not self.audit_resources or (
                    is_resource_filtered(agent_arn, self.audit_resources)
                ):
                    self.agents[agent_arn] = Agent(
                        id=agent["agentId"],
                        name=agent["agentName"],
                        arn=agent_arn,
                        guardrail_id=agent.get("guardrailConfiguration", {}).get(
                            "guardrailIdentifier"
                        ),
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, resource):
        logger.info("Bedrock Agent - Listing Tags for Resource...")
        try:
            agent_tags = (
                self.regional_clients[resource.region]
                .list_tags_for_resource(resourceArn=resource.arn)
                .get("tags", {})
            )
            if agent_tags:
                resource.tags = [agent_tags]
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Agent(BaseModel):
    id: str
    name: str
    arn: str
    guardrail_id: Optional[str]
    region: str
    tags: Optional[list] = []
