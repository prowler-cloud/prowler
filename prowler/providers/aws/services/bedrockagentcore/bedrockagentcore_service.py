from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class BedrockAgentCore(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("bedrock-agentcore-control", provider)
        self.agent_runtimes = {}
        self.agent_runtimes_scan_errors = {}
        self.__threading_call__(self._list_agent_runtimes)
        self.__threading_call__(self._get_agent_runtime, self.agent_runtimes.values())
        self.__threading_call__(
            self._list_tags_for_resource, self.agent_runtimes.values()
        )

    def _list_agent_runtimes(self, regional_client):
        logger.info("Bedrock AgentCore - Listing Agent Runtimes...")
        try:
            paginator = regional_client.get_paginator("list_agent_runtimes")
            for page in paginator.paginate():
                for runtime in page.get("agentRuntimes", []):
                    runtime_id = runtime.get("agentRuntimeId", "")
                    runtime_arn = (
                        runtime.get("agentRuntimeArn")
                        or f"arn:{self.audited_partition}:bedrock-agentcore:{regional_client.region}:{self.audited_account}:runtime/{runtime_id}"
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
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException, ResourceNotFoundException, UnrecognizedClientException,
            # and UnknownOperationException indicate the service is not supported in the region.
            if code not in (
                "ValidationException",
                "ResourceNotFoundException",
                "UnrecognizedClientException",
                "UnknownOperationException",
            ):
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
        logger.info("Bedrock AgentCore - Getting Agent Runtime...")
        try:
            runtime_info = self.regional_clients[runtime.region].get_agent_runtime(
                agentRuntimeId=runtime.id
            )
            authorizer_config = runtime_info.get("authorizerConfiguration", {})
            custom_jwt = authorizer_config.get("customJWTAuthorizer")
            if custom_jwt:
                runtime.authorizer_configuration = AuthorizerConfiguration(
                    custom_jwt_authorizer=CustomJWTAuthorizerConfiguration(
                        discovery_url=custom_jwt.get("discoveryUrl"),
                        allowed_audiences=custom_jwt.get("allowedAudience", []),
                        allowed_clients=custom_jwt.get("allowedClients", []),
                    )
                )
            else:
                runtime.authorizer_configuration = AuthorizerConfiguration()
            runtime.role_arn = runtime_info.get("roleArn")
            runtime.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{runtime.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, runtime):
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


class CustomJWTAuthorizerConfiguration(BaseModel):
    discovery_url: Optional[str] = None
    allowed_audiences: Optional[list[str]] = []
    allowed_clients: Optional[list[str]] = []


class AuthorizerConfiguration(BaseModel):
    custom_jwt_authorizer: Optional[CustomJWTAuthorizerConfiguration] = None


class AgentRuntime(BaseModel):
    id: str
    name: str
    arn: str
    version: Optional[str] = None
    status: Optional[str] = None
    role_arn: Optional[str] = None
    description: Optional[str] = None
    authorizer_configuration: Optional[AuthorizerConfiguration] = None
    region: str
    tags: Optional[dict] = {}
    detail_retrieved: bool = False
