from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.service.service import AWSService


class BedrockAgentCore(AWSService):
    """Bedrock AgentCore control-plane service class."""

    def __init__(self, provider: AwsProvider) -> None:
        """Initialize the BedrockAgentCore service."""
        # bedrock-agentcore-control is the control-plane boto3 service name;
        # it differs from this class's name, so pass it explicitly.
        super().__init__("bedrock-agentcore-control", provider)
        self.memories = {}
        self.gateways = {}
        self.agent_runtimes = {}
        self.code_interpreters = {}
        self.browsers = {}
        self.token_vaults = {}
        self.gateway_targets = {}
        # One error store per listing, keyed by Region. A single shared store
        # cannot work: six collectors run per Region, so one collector's success
        # would mask another's failure and a check reading it could not tell
        # which inventory is incomplete. A Region absent from a store was listed
        # successfully, so an empty inventory there means "none", not "unknown".
        self.memories_scan_errors = {}
        self.gateways_scan_errors = {}
        self.agent_runtimes_scan_errors = {}
        self.code_interpreters_scan_errors = {}
        self.browsers_scan_errors = {}
        self.token_vaults_scan_errors = {}
        self.__threading_call__(self._list_memories)
        self.__threading_call__(self._get_memory, self.memories.values())
        self.__threading_call__(self._list_gateways)
        self.__threading_call__(self._get_gateway, self.gateways.values())
        self.__threading_call__(self._list_gateway_targets, self.gateways.values())
        self.__threading_call__(self._get_gateway_target, self.gateway_targets.values())
        self.__threading_call__(self._list_agent_runtimes)
        self.__threading_call__(self._get_agent_runtime, self.agent_runtimes.values())
        self.__threading_call__(self._list_code_interpreters)
        self.__threading_call__(
            self._get_code_interpreter, self.code_interpreters.values()
        )
        self.__threading_call__(self._list_browsers)
        self.__threading_call__(self._get_browser, self.browsers.values())
        self.__threading_call__(self._get_token_vault)

    def _list_memories(self, regional_client):
        """Collect AgentCore memory resources in one Region.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        Records a failure in ``memories_scan_errors`` keyed by Region, so a check can tell an empty
        Region from an unreadable one. A ``ValidationException`` is treated as "AgentCore is not
        available here" and is deliberately not recorded.
        """
        logger.info("Bedrock AgentCore - Listing Memories...")
        try:
            paginator = regional_client.get_paginator("list_memories")
            for page in paginator.paginate():
                for memory in page.get("memories", []):
                    memory_id = memory.get("id", "")
                    # Both arn and id are optional members of the MemorySummary,
                    # unlike every other AgentCore listing, so fall back to
                    # building the ARN from the id rather than dropping a memory
                    # resource that the account really has.
                    memory_arn = memory.get("arn", "") or (
                        f"arn:{self.audited_partition}:bedrock-agentcore:{regional_client.region}:{self.audited_account}:memory/{memory_id}"
                        if memory_id
                        else ""
                    )
                    # And the mirror case, which the fallback above does not cover: an ARN with no
                    # id. Storing id="" there makes _get_memory call GetMemory(memoryId=""), which
                    # the API rejects outright -- memoryId is min=12 with a pattern at the pin -- so
                    # the resource would be listed and then never enriched, leaving detail_retrieved
                    # False for a reason that has nothing to do with permissions. The id is the last
                    # ARN segment, so recover it rather than issuing a call that cannot succeed.
                    if not memory_id and memory_arn:
                        memory_id = memory_arn.rsplit("/", 1)[-1]
                    if memory_arn and (
                        not self.audit_resources
                        or is_resource_filtered(memory_arn, self.audit_resources)
                    ):
                        self.memories[memory_arn] = AgentCoreMemory(
                            id=memory_id,
                            arn=memory_arn,
                            region=regional_client.region,
                        )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region:
            # a definite "no memories", so it must not become a MANUAL finding.
            if code != "ValidationException":
                self.memories_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.memories_scan_errors[regional_client.region] = error.__class__.__name__
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_memory(self, memory):
        """Enrich one memory resource with its encryption configuration.

        Args:
            memory: The ``AgentCoreMemory`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails, so an absent field reads as unknown
        rather than as "not configured".
        """
        logger.info("Bedrock AgentCore - Getting Memory...")
        try:
            memory_info = (
                self.regional_clients[memory.region]
                .get_memory(memoryId=memory.id)
                .get("memory", {})
            )
            memory.name = memory_info.get("name")
            memory.encryption_key_arn = memory_info.get("encryptionKeyArn")
            memory.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{memory.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_gateways(self, regional_client):
        """Collect AgentCore gateways in one Region.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        Records a failure in ``gateways_scan_errors`` keyed by Region. Gateways are filtered against
        ``audit_resources`` here, which is why their targets are not filtered again later.
        """
        logger.info("Bedrock AgentCore - Listing Gateways...")
        try:
            paginator = regional_client.get_paginator("list_gateways")
            for page in paginator.paginate():
                for gateway in page.get("items", []):
                    gateway_id = gateway.get("gatewayId", "")
                    if not gateway_id:
                        continue
                    gateway_arn = f"arn:{self.audited_partition}:bedrock-agentcore:{regional_client.region}:{self.audited_account}:gateway/{gateway_id}"
                    if not self.audit_resources or is_resource_filtered(
                        gateway_arn, self.audit_resources
                    ):
                        self.gateways[gateway_arn] = AgentCoreGateway(
                            id=gateway_id,
                            name=gateway.get("name", ""),
                            arn=gateway_arn,
                            region=regional_client.region,
                            authorizer_type=gateway.get("authorizerType"),
                        )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region:
            # a definite "no gateways", so it must not become a MANUAL finding.
            if code != "ValidationException":
                self.gateways_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.gateways_scan_errors[regional_client.region] = error.__class__.__name__
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_gateway(self, gateway):
        """Enrich one gateway with its authorizer configuration.

        Args:
            gateway: The ``AgentCoreGateway`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails, because a JWT authorizer's allowed
        clients and audience cannot be distinguished from "unset" once the call is lost.
        """
        logger.info("Bedrock AgentCore - Getting Gateway...")
        try:
            gateway_info = self.regional_clients[gateway.region].get_gateway(
                gatewayIdentifier=gateway.id
            )
            # authorizerType is a required member of the ListGateways summary, so
            # the value already on the gateway is known good. Only overwrite it
            # when GetGateway actually returned one, or a response missing the
            # field would discard a known answer and turn the gateway into an
            # unknown that this check then skips.
            gateway.authorizer_type = (
                gateway_info.get("authorizerType") or gateway.authorizer_type
            )
            jwt_authorizer = gateway_info.get("authorizerConfiguration", {}).get(
                "customJWTAuthorizer", {}
            )
            gateway.custom_jwt_allowed_clients = jwt_authorizer.get(
                "allowedClients", []
            )
            gateway.custom_jwt_allowed_audience = jwt_authorizer.get(
                "allowedAudience", []
            )
            gateway.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{gateway.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_agent_runtimes(self, regional_client):
        """Collect AgentCore agent runtimes in one Region.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        Records a failure in ``agent_runtimes_scan_errors`` keyed by Region.
        """
        logger.info("Bedrock AgentCore - Listing Agent Runtimes...")
        try:
            paginator = regional_client.get_paginator("list_agent_runtimes")
            for page in paginator.paginate():
                for runtime in page.get("agentRuntimes", []):
                    runtime_arn = runtime.get("agentRuntimeArn", "")
                    if runtime_arn and (
                        not self.audit_resources
                        or is_resource_filtered(runtime_arn, self.audit_resources)
                    ):
                        self.agent_runtimes[runtime_arn] = AgentCoreRuntime(
                            id=runtime.get("agentRuntimeId", ""),
                            name=runtime.get("agentRuntimeName", ""),
                            arn=runtime_arn,
                            region=regional_client.region,
                        )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region:
            # a definite "no agent runtimes", so it must not become a MANUAL finding.
            if code != "ValidationException":
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
        """Enrich one agent runtime with its network and authorizer configuration.

        Args:
            runtime: The ``AgentCoreRuntime`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails.
        """
        logger.info("Bedrock AgentCore - Getting Agent Runtime...")
        try:
            runtime_info = self.regional_clients[runtime.region].get_agent_runtime(
                agentRuntimeId=runtime.id
            )
            authorizer_configuration = runtime_info.get("authorizerConfiguration")
            runtime.authorizer_configuration = authorizer_configuration
            jwt_authorizer = (authorizer_configuration or {}).get(
                "customJWTAuthorizer", {}
            )
            runtime.custom_jwt_allowed_clients = jwt_authorizer.get(
                "allowedClients", []
            )
            runtime.custom_jwt_allowed_audience = jwt_authorizer.get(
                "allowedAudience", []
            )
            runtime.network_mode = runtime_info.get("networkConfiguration", {}).get(
                "networkMode"
            )
            runtime.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{runtime.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_code_interpreters(self, regional_client):
        """Collect code interpreters in one Region, once per ``type`` enum value.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        Paginates for ``SYSTEM`` and ``CUSTOM`` separately rather than relying on the default:
        measured at the pin, the no-argument call returns only the CUSTOM interpreters and omits the
        AWS built-in ``aws.codeinterpreter.v1``. Records failures in
        ``code_interpreters_scan_errors``.
        """
        logger.info("Bedrock AgentCore - Listing Code Interpreters...")
        try:
            # Same shape as ListBrowsers, with the documentation one step worse: the
            # ListCodeInterpreters summary also reads "Lists all custom code interpreters in your
            # account", and its `type` parameter says only "The type of code interpreters to
            # list" -- it makes no claim at all about the default. Measured: the no-argument call
            # returns only CUSTOM (3 in the probe account) and omits the SYSTEM built-in
            # aws.codeinterpreter.v1. Both enum values are paginated explicitly.
            for interpreter_type in ("SYSTEM", "CUSTOM"):
                paginator = regional_client.get_paginator("list_code_interpreters")
                for page in paginator.paginate(type=interpreter_type):
                    for code_interpreter in page.get("codeInterpreterSummaries", []):
                        code_interpreter_arn = code_interpreter.get(
                            "codeInterpreterArn", ""
                        )
                        if code_interpreter_arn and (
                            not self.audit_resources
                            or is_resource_filtered(
                                code_interpreter_arn, self.audit_resources
                            )
                        ):
                            self.code_interpreters[code_interpreter_arn] = (
                                AgentCoreCodeInterpreter(
                                    id=code_interpreter.get("codeInterpreterId", ""),
                                    name=code_interpreter.get("name", ""),
                                    arn=code_interpreter_arn,
                                    region=regional_client.region,
                                )
                            )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region:
            # a definite "no code interpreters", so it must not become a MANUAL finding.
            if code != "ValidationException":
                self.code_interpreters_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.code_interpreters_scan_errors[regional_client.region] = (
                error.__class__.__name__
            )
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_code_interpreter(self, code_interpreter):
        """Enrich one code interpreter with its network configuration.

        Args:
            code_interpreter: The ``AgentCoreCodeInterpreter`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails.
        """
        logger.info("Bedrock AgentCore - Getting Code Interpreter...")
        try:
            code_interpreter_info = self.regional_clients[
                code_interpreter.region
            ].get_code_interpreter(codeInterpreterId=code_interpreter.id)
            code_interpreter.network_mode = code_interpreter_info.get(
                "networkConfiguration", {}
            ).get("networkMode")
            code_interpreter.execution_role_arn = code_interpreter_info.get(
                "executionRoleArn"
            )
            code_interpreter.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{code_interpreter.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_browsers(self, regional_client):
        """Collect browsers in one Region, once per ``type`` enum value.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        Paginates for ``SYSTEM`` and ``CUSTOM`` separately for the same reason as the code
        interpreters: the default omits the AWS built-in ``aws.browser.v1``. Records failures in
        ``browsers_scan_errors``.
        """
        logger.info("Bedrock AgentCore - Listing Browsers...")
        try:
            # AWS's own ListBrowsers page contradicts itself: the operation summary reads
            # "Lists all custom browsers in your account" while the `type` parameter reads
            # "If not specified, all browser types are returned." Measured at the pin against a
            # live account, the summary is the one that holds -- the no-argument call returns
            # only the CUSTOM browsers and silently omits the SYSTEM built-in (2 with no
            # argument; type=SYSTEM adds aws.browser.v1). Since the three checks reading this
            # inventory are about the built-in tools as much as custom ones, dropping the
            # SYSTEM entry would under-report rather than merely under-count, so both enum
            # values are paginated explicitly.
            #
            # A correction, recorded because the wrong version shipped in an earlier revision of
            # this file: that comment claimed the no-argument call "returns 0". It does not. The
            # original measurement was taken in an account that happened to own no CUSTOM
            # browser, so "no CUSTOM browsers" was mistaken for "no browsers at all".
            for browser_type in ("SYSTEM", "CUSTOM"):
                paginator = regional_client.get_paginator("list_browsers")
                for page in paginator.paginate(type=browser_type):
                    for browser in page.get("browserSummaries", []):
                        browser_arn = browser.get("browserArn", "")
                        if browser_arn and (
                            not self.audit_resources
                            or is_resource_filtered(browser_arn, self.audit_resources)
                        ):
                            self.browsers[browser_arn] = AgentCoreBrowser(
                                id=browser.get("browserId", ""),
                                name=browser.get("name", ""),
                                arn=browser_arn,
                                region=regional_client.region,
                            )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region:
            # a definite "no browsers", so it must not become a MANUAL finding.
            if code != "ValidationException":
                self.browsers_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.browsers_scan_errors[regional_client.region] = error.__class__.__name__
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_browser(self, browser):
        """Enrich one browser with its network and recording configuration.

        Args:
            browser: The ``AgentCoreBrowser`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails, which is what lets a check report
        MANUAL instead of asserting that session recording is off.
        """
        logger.info("Bedrock AgentCore - Getting Browser...")
        try:
            browser_info = self.regional_clients[browser.region].get_browser(
                browserId=browser.id
            )
            browser.network_mode = browser_info.get("networkConfiguration", {}).get(
                "networkMode"
            )
            recording = browser_info.get("recording")
            # No recording block at all means recording is off. A block that
            # omits enabled leaves it unknown, which the check reports rather
            # than reading as disabled.
            #
            # `is not None`, NOT truthiness: `RecordingConfig.enabled` is optional at the pin
            # (required_members is empty), so `"recording": {}` is a legal response -- and it is
            # exactly the "block that omits enabled" the comment above describes. Testing
            # truthiness made that empty block falsy and reported recording as definitely OFF,
            # which contradicted this comment and would let a browser whose recording state is
            # unknown be reported as a definite finding.
            browser.recording_enabled = (
                recording.get("enabled") if recording is not None else False
            )
            browser.execution_role_arn = browser_info.get("executionRoleArn")
            browser.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{browser.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_token_vault(self, regional_client):
        """Collect the account's token vault for one Region.

        Args:
            regional_client: The regional ``bedrock-agentcore-control`` client.

        There is no list operation, so this is both the discovery and the enrichment call. A
        ``ResourceNotFoundException`` means the Region genuinely has no vault and is not recorded as
        an error; anything else is recorded in ``token_vaults_scan_errors``.
        """
        logger.info("Bedrock AgentCore - Getting Token Vault...")
        try:
            vault_info = regional_client.get_token_vault()
            vault_id = vault_info.get("tokenVaultId", "default")
            vault_arn = f"arn:{self.audited_partition}:bedrock-agentcore:{regional_client.region}:{self.audited_account}:token-vault/{vault_id}"
            if not self.audit_resources or is_resource_filtered(
                vault_arn, self.audit_resources
            ):
                self.token_vaults[vault_arn] = AgentCoreTokenVault(
                    id=vault_id,
                    arn=vault_arn,
                    region=regional_client.region,
                    kms_key_type=vault_info.get("kmsConfiguration", {}).get("keyType"),
                    detail_retrieved=True,
                )
        except ClientError as error:
            code = error.response["Error"].get("Code", error.__class__.__name__)
            # ValidationException means AgentCore is unavailable in the region and
            # ResourceNotFoundException means the account has no vault there, so
            # neither is an unknown that warrants a MANUAL finding.
            if code not in ("ValidationException", "ResourceNotFoundException"):
                self.token_vaults_scan_errors[regional_client.region] = code
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            self.token_vaults_scan_errors[regional_client.region] = (
                error.__class__.__name__
            )
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_gateway_targets(self, gateway):
        """Collect the targets of one gateway.

        Args:
            gateway: The ``AgentCoreGateway`` whose targets to collect.

        Targets are listed per gateway, so a failure is recorded on the gateway itself
        (``targets_error``, and ``targets_listed`` stays False) rather than in a Region-keyed store:
        one gateway's unreadable target list must not mark every other gateway in the Region unknown.
        The synthetic target ARN is deliberately not filtered against ``audit_resources`` -- AWS
        exposes no ARN for a gateway target, so a synthetic one could never match a user-supplied
        ``--resource-arn`` and filtering on it would drop every target of an in-scope gateway.
        """
        logger.info("Bedrock AgentCore - Listing Gateway Targets...")
        try:
            paginator = self.regional_clients[gateway.region].get_paginator(
                "list_gateway_targets"
            )
            for page in paginator.paginate(gatewayIdentifier=gateway.id):
                for target in page.get("items", []):
                    target_id = target.get("targetId", "")
                    if not target_id:
                        continue
                    # No filter here: the parent gateway was already filtered on
                    # its own ARN, and this ARN is synthetic because AWS exposes
                    # none for a gateway target, so it could never match a
                    # user-supplied --resource-arn and would silently drop every
                    # target of an in-scope gateway.
                    target_arn = f"{gateway.arn}/target/{target_id}"
                    self.gateway_targets[target_arn] = AgentCoreGatewayTarget(
                        id=target_id,
                        name=target.get("name", ""),
                        arn=target_arn,
                        region=gateway.region,
                        gateway_id=gateway.id,
                        gateway_name=gateway.name,
                    )
            gateway.targets_listed = True
        except ClientError as error:
            gateway.targets_error = error.response["Error"].get(
                "Code", error.__class__.__name__
            )
            logger.error(
                f"{gateway.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            gateway.targets_error = error.__class__.__name__
            logger.error(
                f"{gateway.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_gateway_target(self, target):
        """Enrich one gateway target with its credential provider and target configuration.

        Args:
            target: The ``AgentCoreGatewayTarget`` to enrich in place.

        Leaves ``detail_retrieved`` False when the call fails. Credential provider entries with no
        ``credentialProviderType`` are dropped rather than recorded as None.
        """
        logger.info("Bedrock AgentCore - Getting Gateway Target...")
        try:
            info = self.regional_clients[target.region].get_gateway_target(
                gatewayIdentifier=target.gateway_id, targetId=target.id
            )
            target.credential_provider_types = [
                c.get("credentialProviderType")
                for c in info.get("credentialProviderConfigurations", [])
                if c.get("credentialProviderType")
            ]
            target.target_configuration = info.get("targetConfiguration", {})
            target.detail_retrieved = True
        except Exception as error:
            logger.error(
                f"{target.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class AgentCoreMemory(BaseModel):
    """Model representing a Bedrock AgentCore memory resource."""

    id: str
    name: Optional[str] = None
    arn: str
    region: str
    encryption_key_arn: Optional[str] = None
    # False when the Get* call failed (AccessDenied, throttle), so an absent
    # field means "unknown" rather than "not configured".
    detail_retrieved: bool = False


class AgentCoreGateway(BaseModel):
    """Model representing a Bedrock AgentCore gateway resource."""

    id: str
    name: str
    arn: str
    region: str
    authorizer_type: Optional[str] = None
    custom_jwt_allowed_clients: list = []
    custom_jwt_allowed_audience: list = []
    # False when GetGateway failed (AccessDenied, throttle), so an absent field
    # means "unknown" rather than "not configured".
    detail_retrieved: bool = False
    # True once ListGatewayTargets succeeded, so no target for this gateway means
    # it genuinely has none rather than that they could not be listed.
    targets_listed: bool = False
    targets_error: Optional[str] = None


class AgentCoreRuntime(BaseModel):
    """Model representing a Bedrock AgentCore agent runtime resource."""

    id: str
    name: str
    arn: str
    region: str
    authorizer_configuration: Optional[dict] = None
    custom_jwt_allowed_clients: list = []
    custom_jwt_allowed_audience: list = []
    network_mode: Optional[str] = None
    # False when the Get* call failed (AccessDenied, throttle), so an absent
    # field means "unknown" rather than "not configured".
    detail_retrieved: bool = False


class AgentCoreCodeInterpreter(BaseModel):
    """Model representing a Bedrock AgentCore code interpreter tool resource."""

    id: str
    name: str
    arn: str
    region: str
    network_mode: Optional[str] = None
    execution_role_arn: Optional[str] = None
    # False when the Get* call failed (AccessDenied, throttle), so an absent
    # field means "unknown" rather than "not configured".
    detail_retrieved: bool = False


class AgentCoreBrowser(BaseModel):
    """Model representing a Bedrock AgentCore browser tool resource."""

    id: str
    name: str
    arn: str
    region: str
    network_mode: Optional[str] = None
    # None when the browser reports a recording block with no explicit enabled
    # flag: it is an optional member with no documented default, so it is unknown
    # rather than false. An absent recording block is a definite "not recording".
    recording_enabled: Optional[bool] = None
    execution_role_arn: Optional[str] = None
    # False when the Get* call failed (AccessDenied, throttle), so an absent
    # field means "unknown" rather than "not configured".
    detail_retrieved: bool = False


class AgentCoreTokenVault(BaseModel):
    """Model representing a Bedrock AgentCore token vault resource."""

    id: str
    arn: str
    region: str
    kms_key_type: Optional[str] = None
    # False when GetTokenVault failed. keyType is a required member of its
    # response, so an absent value can only mean the call did not answer, never
    # that the vault uses a service-managed key.
    detail_retrieved: bool = False


class AgentCoreGatewayTarget(BaseModel):
    """Model representing a Bedrock AgentCore gateway target resource."""

    id: str
    name: str
    arn: str
    region: str
    gateway_id: str
    gateway_name: Optional[str] = None
    credential_provider_types: list = []
    target_configuration: dict = {}
    detail_retrieved: bool = False
