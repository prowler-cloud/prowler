from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Bedrock(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.logging_configurations = {}
        self.guardrails = {}
        self.guardrails_scanned_regions = set()
        self.guardrails_scan_errors = {}
        self.custom_models = {}
        self.__threading_call__(self._get_model_invocation_logging_configuration)
        self.__threading_call__(self._list_guardrails)
        self.__threading_call__(self._get_guardrail, self.guardrails.values())
        self.__threading_call__(self._list_tags_for_resource, self.guardrails.values())
        self.__threading_call__(self._list_custom_models)
        self.__threading_call__(self._get_custom_model, self.custom_models.values())

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
            paginator = regional_client.get_paginator("list_guardrails")
            for page in paginator.paginate():
                for guardrail in page.get("guardrails", []):
                    if not self.audit_resources or (
                        is_resource_filtered(guardrail["arn"], self.audit_resources)
                    ):
                        self.guardrails[guardrail["arn"]] = Guardrail(
                            id=guardrail["id"],
                            name=guardrail["name"],
                            arn=guardrail["arn"],
                            region=regional_client.region,
                        )
            self.guardrails_scanned_regions.add(regional_client.region)
        except ClientError as error:
            self.guardrails_scan_errors[regional_client.region] = error.response[
                "Error"
            ].get("Code", error.__class__.__name__)
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.guardrails_scan_errors[regional_client.region] = (
                error.__class__.__name__
            )
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
            # contextualGroundingPolicy is absent from the response when no
            # grounding policy is configured, so an empty list means "none
            # configured" only once detail_retrieved is True.
            guardrail.contextual_grounding_filters = [
                {
                    "type": filter.get("type"),
                    "threshold": filter.get("threshold"),
                    "action": filter.get("action"),
                    "enabled": filter.get("enabled"),
                }
                for filter in guardrail_info.get("contextualGroundingPolicy", {}).get(
                    "filters", []
                )
            ]
            guardrail.detail_retrieved = True
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

    def _list_custom_models(self, regional_client):
        """List the customized models owned by the audited account."""
        logger.info("Bedrock - Listing Custom Models...")
        try:
            paginator = regional_client.get_paginator("list_custom_models")
            for page in paginator.paginate():
                for model in page.get("modelSummaries", []):
                    model_arn = model.get("modelArn", "")
                    if model_arn and (
                        not self.audit_resources
                        or is_resource_filtered(model_arn, self.audit_resources)
                    ):
                        self.custom_models[model_arn] = CustomModel(
                            name=model.get("modelName", ""),
                            arn=model_arn,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_custom_model(self, model):
        """Fetch the KMS key a custom model's weights are encrypted with.

        list_custom_models summaries do not carry modelKmsKeyArn, so a
        per-model GetCustomModel call is required.
        """
        logger.info("Bedrock - Getting Custom Model...")
        try:
            model_info = self.regional_clients[model.region].get_custom_model(
                modelIdentifier=model.arn
            )
            model.kms_key_arn = model_info.get("modelKmsKeyArn")
            model.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{model.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
    prompt_attack_filter_strength: Optional[str] = None
    # One dict per contextualGroundingPolicy filter: type, threshold, action,
    # enabled. Empty when no grounding policy is configured.
    contextual_grounding_filters: list = []
    # False when GetGuardrail failed, so an absent policy means "unknown"
    # rather than "not configured".
    detail_retrieved: bool = False


class CustomModel(BaseModel):
    """Model representing a Bedrock customized (fine-tuned) model."""

    name: str
    arn: str
    region: str
    kms_key_arn: Optional[str] = None
    # False when GetCustomModel failed, so an absent key ARN means "unknown"
    # rather than "AWS-owned key".
    detail_retrieved: bool = False


class BedrockAgent(AWSService):
    """Bedrock Agent service class for managing agents and prompts."""

    def __init__(self, provider):
        """Initialize the BedrockAgent service."""
        # Call AWSService's __init__
        super().__init__("bedrock-agent", provider)
        self.agents = {}
        self.prompts = {}
        self.knowledge_bases = {}
        self.data_sources = {}
        self.prompt_scanned_regions: set = set()
        self.__threading_call__(self._list_agents)
        self.__threading_call__(self._get_agent, self.agents.values())
        self.__threading_call__(self._list_prompts)
        self.__threading_call__(self._get_prompt, self.prompts.values())
        self.__threading_call__(self._list_tags_for_resource, self.agents.values())
        self.__threading_call__(self._list_knowledge_bases)
        self.__threading_call__(self._list_data_sources, self.knowledge_bases.values())
        self.__threading_call__(self._get_data_source, self.data_sources.values())

    def _list_agents(self, regional_client):
        logger.info("Bedrock Agent - Listing Agents...")
        try:
            paginator = regional_client.get_paginator("list_agents")
            for page in paginator.paginate():
                for agent in page.get("agentSummaries", []):
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

    def _get_agent(self, agent):
        """Fetch full agent details to capture the execution role ARN.

        list_agents only returns summaries (no agentResourceRoleArn), so we
        need a per-agent GetAgent call. Stored on the Agent model for use by
        checks like bedrock_agent_role_least_privilege.
        """
        logger.info("Bedrock Agent - Getting Agent...")
        try:
            agent_info = self.regional_clients[agent.region].get_agent(agentId=agent.id)
            agent.role_arn = agent_info.get("agent", {}).get("agentResourceRoleArn")
            agent.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{agent.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_prompts(self, regional_client):
        """List all prompts in a region."""
        logger.info("Bedrock Agent - Listing Prompts...")
        try:
            paginator = regional_client.get_paginator("list_prompts")
            for page in paginator.paginate():
                for prompt in page.get("promptSummaries", []):
                    prompt_arn = prompt.get("arn", "")
                    if not self.audit_resources or (
                        is_resource_filtered(prompt_arn, self.audit_resources)
                    ):
                        self.prompts[prompt_arn] = Prompt(
                            id=prompt.get("id", ""),
                            name=prompt.get("name", ""),
                            arn=prompt_arn,
                            region=regional_client.region,
                            version=prompt.get("version"),
                        )
            self.prompt_scanned_regions.add(regional_client.region)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_prompt(self, prompt):
        """Get detailed prompt information including encryption configuration."""
        logger.info("Bedrock Agent - Getting Prompt...")
        try:
            prompt_info = self.regional_clients[prompt.region].get_prompt(
                promptIdentifier=prompt.id
            )
            prompt.customer_encryption_key_arn = prompt_info.get(
                "customerEncryptionKeyArn"
            )
            # ListPrompts already returns version as a required member, so it
            # wins; GetPrompt only fills the gap when the summary omitted it.
            prompt.version = prompt.version or prompt_info.get("version")
        except Exception as error:
            logger.error(
                f"{prompt.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_knowledge_bases(self, regional_client):
        """List the knowledge bases in a region."""
        logger.info("Bedrock Agent - Listing Knowledge Bases...")
        try:
            paginator = regional_client.get_paginator("list_knowledge_bases")
            for page in paginator.paginate():
                for knowledge_base in page.get("knowledgeBaseSummaries", []):
                    knowledge_base_id = knowledge_base.get("knowledgeBaseId", "")
                    if not knowledge_base_id:
                        continue
                    knowledge_base_arn = f"arn:{self.audited_partition}:bedrock:{regional_client.region}:{self.audited_account}:knowledge-base/{knowledge_base_id}"
                    if not self.audit_resources or is_resource_filtered(
                        knowledge_base_arn, self.audit_resources
                    ):
                        self.knowledge_bases[knowledge_base_arn] = KnowledgeBase(
                            id=knowledge_base_id,
                            name=knowledge_base.get("name", ""),
                            arn=knowledge_base_arn,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_data_sources(self, knowledge_base):
        """List the data sources attached to one knowledge base."""
        logger.info("Bedrock Agent - Listing Data Sources...")
        try:
            paginator = self.regional_clients[knowledge_base.region].get_paginator(
                "list_data_sources"
            )
            for page in paginator.paginate(knowledgeBaseId=knowledge_base.id):
                for data_source in page.get("dataSourceSummaries", []):
                    data_source_id = data_source.get("dataSourceId", "")
                    if not data_source_id:
                        continue
                    data_source_arn = (
                        f"{knowledge_base.arn}/data-source/{data_source_id}"
                    )
                    if not self.audit_resources or is_resource_filtered(
                        data_source_arn, self.audit_resources
                    ):
                        self.data_sources[data_source_arn] = KnowledgeBaseDataSource(
                            id=data_source_id,
                            name=data_source.get("name", ""),
                            arn=data_source_arn,
                            region=knowledge_base.region,
                            knowledge_base_id=knowledge_base.id,
                            knowledge_base_name=knowledge_base.name,
                        )
        except Exception as error:
            logger.error(
                f"{knowledge_base.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_data_source(self, data_source):
        """Fetch the KMS key a data source's transient storage is encrypted with."""
        logger.info("Bedrock Agent - Getting Data Source...")
        try:
            # GetDataSource nests everything under a top-level dataSource object.
            data_source_info = (
                self.regional_clients[data_source.region]
                .get_data_source(
                    knowledgeBaseId=data_source.knowledge_base_id,
                    dataSourceId=data_source.id,
                )
                .get("dataSource", {})
            )
            data_source.kms_key_arn = data_source_info.get(
                "serverSideEncryptionConfiguration", {}
            ).get("kmsKeyArn")
            data_source.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{data_source.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, resource):
        """List tags for a Bedrock Agent resource."""
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
    """Model for a Bedrock Agent resource."""

    id: str
    name: str
    arn: str
    guardrail_id: Optional[str] = None
    role_arn: Optional[str] = None
    region: str
    tags: Optional[list] = []
    # False when GetAgent failed, so an absent role ARN means "unknown" rather
    # than "no execution role".
    detail_retrieved: bool = False


class Prompt(BaseModel):
    """Model representing a Bedrock Prompt Management prompt."""

    id: str
    name: str
    arn: str
    region: str
    customer_encryption_key_arn: Optional[str] = None
    # "DRAFT" is the mutable working copy; anything else is an immutable
    # numbered version.
    version: Optional[str] = None


class KnowledgeBase(BaseModel):
    """Model representing a Bedrock Agent knowledge base."""

    id: str
    name: str
    arn: str
    region: str


class KnowledgeBaseDataSource(BaseModel):
    """Model representing a data source attached to a Bedrock knowledge base."""

    id: str
    name: str
    arn: str
    region: str
    knowledge_base_id: str
    knowledge_base_name: Optional[str] = None
    kms_key_arn: Optional[str] = None
    # False when GetDataSource failed, so an absent key ARN means "unknown"
    # rather than "AWS-owned key".
    detail_retrieved: bool = False
