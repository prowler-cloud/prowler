from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

# Errors that mean AgentCore is not available in the region, not an
# unreadable inventory. These must not become MANUAL findings.
_UNSUPPORTED_REGION_ERROR_CODES = (
    "ValidationException",
    "ResourceNotFoundException",
    "UnrecognizedClientException",
    "UnknownOperationException",
)


class BedrockAgentCore(AWSService):
    """Amazon Bedrock AgentCore control-plane collector."""

    def __init__(self, provider):
        """Initialize the Bedrock AgentCore service.

        Args:
            provider: Prowler AWS provider object.
        """
        super().__init__("bedrock-agentcore-control", provider)
        self.agent_runtimes = {}
        self.agent_runtimes_scan_errors = {}
        self.__threading_call__(self._list_agent_runtimes)
        self.__threading_call__(self._get_agent_runtime, self.agent_runtimes.values())
        self.__threading_call__(
            self._list_tags_for_resource, self.agent_runtimes.values()
        )

    def _list_agent_runtimes(self, regional_client):
        """List Bedrock AgentCore runtimes in a region.

        Args:
            regional_client: Regional Bedrock AgentCore boto3 client.
        """
        logger.info("Bedrock AgentCore - Listing Agent Runtimes...")
        try:
            paginator = regional_client.get_paginator("list_agent_runtimes")
            for page in paginator.paginate():
                try:
                    for runtime in page.get("agentRuntimes", []):
                        runtime_id = runtime.get("agentRuntimeId", "")
                        runtime_arn = runtime.get("agentRuntimeArn") or (
                            f"arn:{self.audited_partition}:bedrock-agentcore:"
                            f"{regional_client.region}:{self.audited_account}:"
                            f"runtime/{runtime_id}"
                        )
                        if not self.audit_resources or is_resource_filtered(
                            runtime_arn, self.audit_resources
                        ):
                            self.agent_runtimes[runtime_arn] = AgentRuntime(
                                id=runtime_id,
                                name=runtime.get("agentRuntimeName") or runtime_id,
                                arn=runtime_arn,
                                version=runtime.get("agentRuntimeVersion"),
                                status=runtime.get("status"),
                                description=runtime.get("description"),
                                region=regional_client.region,
                            )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            if code not in _UNSUPPORTED_REGION_ERROR_CODES:
                self.agent_runtimes_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.agent_runtimes_scan_errors[regional_client.region] = (
                error.__class__.__name__
            )
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_agent_runtime(self, runtime):
        """Get detailed configuration for a Bedrock AgentCore runtime.

        Args:
            runtime: AgentRuntime instance to enrich with network configuration.
        """
        logger.info("Bedrock AgentCore - Getting Agent Runtime...")
        try:
            runtime_info = self.regional_clients[runtime.region].get_agent_runtime(
                agentRuntimeId=runtime.id
            )
            network_config = runtime_info.get("networkConfiguration") or {}
            runtime.network_mode = network_config.get("networkMode")
            mode_config = network_config.get("networkModeConfig") or {}
            runtime.network_mode_config = VpcNetworkModeConfig(
                subnets=mode_config.get("subnets") or [],
                security_groups=mode_config.get("securityGroups") or [],
            )
            runtime.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{runtime.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, runtime):
        """List tags for a Bedrock AgentCore runtime.

        Args:
            runtime: AgentRuntime instance to attach tags to.
        """
        logger.info("Bedrock AgentCore - Listing Tags for Resource...")
        try:
            runtime.tags = (
                self.regional_clients[runtime.region]
                .list_tags_for_resource(resourceArn=runtime.arn)
                .get("tags", {})
            )
        except Exception as error:
            logger.error(
                f"{runtime.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VpcNetworkModeConfig(BaseModel):
    """VPC network mode configuration for an AgentCore runtime."""

    subnets: list[str] = []
    security_groups: list[str] = []


class AgentRuntime(BaseModel):
    """Bedrock AgentCore runtime resource model."""

    id: str
    name: str
    arn: str
    region: str
    version: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    network_mode: Optional[str] = None
    network_mode_config: Optional[VpcNetworkModeConfig] = None
    tags: Optional[dict] = {}
    detail_retrieved: bool = False
