"""Tests for the Bedrock AgentCore service collectors."""

from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call
MEMORY_ID = "mem-123"
MEMORY_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":memory/{MEMORY_ID}"
)
GATEWAY_ID = "gw-123"
RUNTIME_ID = "rt-123"
RUNTIME_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":runtime/{RUNTIME_ID}"
)
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"


def mock_make_api_call_agentcore(self, operation_name, kwarg):
    """Populate one resource per AgentCore collector."""
    if operation_name == "ListMemories":
        return {"memories": [{"arn": MEMORY_ARN, "id": MEMORY_ID, "name": "mem"}]}
    if operation_name == "GetMemory":
        return {
            "memory": {
                "id": MEMORY_ID,
                "name": "mem",
                "arn": MEMORY_ARN,
                "encryptionKeyArn": KMS_KEY_ARN,
            }
        }
    if operation_name == "ListGateways":
        return {"items": [{"gatewayId": GATEWAY_ID, "name": "gw"}]}
    if operation_name == "GetGateway":
        return {
            "gatewayId": GATEWAY_ID,
            "name": "gw",
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {"allowedClients": ["client-1"]}
            },
        }
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeId": RUNTIME_ID,
                    "agentRuntimeName": "rt",
                }
            ]
        }
    if operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RUNTIME_ID,
            "agentRuntimeName": "rt",
            "agentRuntimeArn": RUNTIME_ARN,
            "networkConfiguration": {"networkMode": "VPC"},
        }
    if operation_name == "ListCodeInterpreters":
        return {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterArn": f"{RUNTIME_ARN}-ci",
                    "codeInterpreterId": "ci-1",
                    "name": "ci",
                }
            ]
        }
    if operation_name == "GetCodeInterpreter":
        return {
            "codeInterpreterId": "ci-1",
            "name": "ci",
            "networkConfiguration": {"networkMode": "SANDBOX"},
        }
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserArn": f"{RUNTIME_ARN}-br",
                    "browserId": "br-1",
                    "name": "br",
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": "br-1",
            "name": "br",
            "networkConfiguration": {"networkMode": "VPC"},
            "recording": {"enabled": True},
        }
    if operation_name == "GetTokenVault":
        return {
            "tokenVaultId": "default",
            "kmsConfiguration": {"keyType": "CustomerManagedKey"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_unsupported(self, operation_name, kwarg):
    """Every AgentCore collector raises — the service must degrade, not crash."""
    if operation_name.startswith(("List", "Get")) and (
        "Memor" in operation_name
        or "Gateway" in operation_name
        or "AgentRuntime" in operation_name
        or "CodeInterpreter" in operation_name
        or "Browser" in operation_name
        or "TokenVault" in operation_name
    ):
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock AgentCore is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_Bedrock_AgentCore_Service:
    """Cover the BedrockAgentCore service class."""

    @mock_aws
    def test_service_and_client(self):
        """The boto3 service name must be the CONTROL plane, not the data plane."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        agentcore = BedrockAgentCore(aws_provider)
        assert agentcore.service == "bedrock-agentcore-control"
        assert agentcore.audited_account == AWS_ACCOUNT_NUMBER
        assert AWS_REGION_US_EAST_1 in agentcore.regional_clients

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_agentcore
    )
    @mock_aws
    def test_all_collectors_populate(self):
        """Each collector stores its resource and the Get* enrichment lands."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ac = BedrockAgentCore(aws_provider)

        assert len(ac.memories) == 1
        memory = next(iter(ac.memories.values()))
        assert memory.id == MEMORY_ID
        assert memory.arn == MEMORY_ARN
        assert memory.region == AWS_REGION_US_EAST_1
        assert memory.encryption_key_arn == KMS_KEY_ARN

        assert len(ac.gateways) == 1
        gateway = next(iter(ac.gateways.values()))
        assert gateway.id == GATEWAY_ID
        # The gateway ARN is CONSTRUCTED by the service; ListGateways does not return one.
        assert gateway.arn.endswith(f":gateway/{GATEWAY_ID}")
        assert gateway.authorizer_type == "CUSTOM_JWT"
        assert gateway.custom_jwt_allowed_clients == ["client-1"]

        assert len(ac.agent_runtimes) == 1
        runtime = next(iter(ac.agent_runtimes.values()))
        assert runtime.id == RUNTIME_ID
        assert runtime.arn == RUNTIME_ARN
        assert runtime.network_mode == "VPC"

        assert len(ac.code_interpreters) == 1
        assert next(iter(ac.code_interpreters.values())).network_mode == "SANDBOX"

        assert len(ac.browsers) == 1
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is True
        assert browser.network_mode == "VPC"

        assert len(ac.token_vaults) == 1
        assert next(iter(ac.token_vaults.values())).kms_key_type == "CustomerManagedKey"

    @mock_aws
    def test_tags_are_read_only_for_resources_the_account_owns(self):
        """Owned resources get their tags; the AWS-owned SYSTEM browser is never tagged."""
        system_browser_arn = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:aws:browser/aws.browser.v1"
        tagged_arns = []

        def _mock(self, operation_name, kwarg):
            if operation_name == "ListTagsForResource":
                tagged_arns.append(kwarg["resourceArn"])
                return {"tags": {"env": "prod"}}
            if operation_name == "ListBrowsers":
                return {
                    "browserSummaries": [
                        {
                            "browserArn": system_browser_arn,
                            "browserId": "aws.browser.v1",
                            "name": "aws.browser.v1",
                        }
                    ]
                }
            return mock_make_api_call_agentcore(self, operation_name, kwarg)

        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        with mock.patch("botocore.client.BaseClient._make_api_call", new=_mock):
            ac = BedrockAgentCore(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        assert ac.memories[MEMORY_ARN].tags == [{"env": "prod"}]
        assert ac.agent_runtimes[RUNTIME_ARN].tags == [{"env": "prod"}]
        assert ac.browsers[system_browser_arn].tags == []
        assert system_browser_arn not in tagged_arns
        assert MEMORY_ARN in tagged_arns

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_unsupported
    )
    @mock_aws
    def test_unsupported_region_degrades_quietly(self):
        """A per-collector ClientError is logged, not raised, and leaves stores empty."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ac = BedrockAgentCore(aws_provider)
        assert ac.memories == {}
        assert ac.gateways == {}
        assert ac.agent_runtimes == {}
        assert ac.code_interpreters == {}
        assert ac.browsers == {}
        assert ac.token_vaults == {}


LISTING_TO_STORE_inventory = {
    "ListMemories": "memories_scan_errors",
    "ListGateways": "gateways_scan_errors",
    "ListAgentRuntimes": "agent_runtimes_scan_errors",
    "ListCodeInterpreters": "code_interpreters_scan_errors",
    "ListBrowsers": "browsers_scan_errors",
    "GetTokenVault": "token_vaults_scan_errors",
}


def _all_calls_raise(code):
    """Build a _make_api_call replacement failing every AgentCore call."""

    def _mock(self, operation_name, kwarg):
        """Raise for every AgentCore listing and delegate anything else to botocore."""
        if operation_name in LISTING_TO_STORE_inventory:
            raise ClientError(
                {"Error": {"Code": code, "Message": "denied"}}, operation_name
            )
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _one_call_raises(failing_operation, code="AccessDeniedException"):
    """Build a replacement failing exactly one listing and emptying the rest."""
    empty = {
        "ListMemories": {"memories": []},
        "ListGateways": {"items": []},
        "ListAgentRuntimes": {"agentRuntimes": []},
        "ListBrowsers": {"browserSummaries": []},
        "ListCodeInterpreters": {"codeInterpreterSummaries": []},
        "GetTokenVault": {"tokenVaultId": "default"},
    }

    def _mock(self, operation_name, kwarg):
        """Raise for the named listing, empty the other listings, delegate the rest."""
        if operation_name == failing_operation:
            raise ClientError(
                {"Error": {"Code": code, "Message": "denied"}}, operation_name
            )
        if operation_name in empty:
            return empty[operation_name]
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _build_service_inventory():
    """Instantiate BedrockAgentCore under the active mock."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ):
        return BedrockAgentCore(aws_provider)


class Test_BedrockAgentCore_inventory_errors:
    """Tests for the per-listing scan-error stores."""

    @mock_aws
    def test_denied_listing_is_recorded_per_collector(self):
        """Each failed listing records its own error, naming the API error code."""
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_all_calls_raise("AccessDeniedException"),
        ):
            service = _build_service_inventory()

        for store in LISTING_TO_STORE_inventory.values():
            assert getattr(service, store) == {
                AWS_REGION_US_EAST_1: "AccessDeniedException"
            }, store

    @mock_aws
    def test_unsupported_region_is_not_recorded_as_an_error(self):
        """ValidationException means the Region has no resources, not unknown ones.

        Recording it would emit a MANUAL finding for every Region AgentCore does
        not serve, in every account, which is noise rather than a finding.
        """
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_all_calls_raise("ValidationException"),
        ):
            service = _build_service_inventory()

        for store in LISTING_TO_STORE_inventory.values():
            assert getattr(service, store) == {}, store

    @mock_aws
    def test_absent_token_vault_is_not_recorded_as_an_error(self):
        """An account with no token vault in a Region is "none", not "unknown"."""
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_all_calls_raise("ResourceNotFoundException"),
        ):
            service = _build_service_inventory()

        assert service.token_vaults_scan_errors == {}
        assert service.token_vaults == {}

    @mock_aws
    def test_one_failed_listing_does_not_mask_the_others(self):
        """Stores are independent, so a success cannot hide a sibling's failure.

        A single shared store would be written by whichever collector ran last,
        so a check reading it could not tell which inventory is incomplete.
        """
        for failing_operation, store in LISTING_TO_STORE_inventory.items():
            with mock.patch(
                "botocore.client.BaseClient._make_api_call",
                new=_one_call_raises(failing_operation),
            ):
                service = _build_service_inventory()

            assert getattr(service, store) == {
                AWS_REGION_US_EAST_1: "AccessDeniedException"
            }, failing_operation
            for other_store in LISTING_TO_STORE_inventory.values():
                if other_store != store:
                    assert (
                        getattr(service, other_store) == {}
                    ), f"{failing_operation} leaked into {other_store}"

    @mock_aws
    def test_successful_listing_records_no_error(self):
        """An empty inventory with no recorded error means "none", not "unknown"."""
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_one_call_raises("NoSuchOperation"),
        ):
            service = _build_service_inventory()

        for store in LISTING_TO_STORE_inventory.values():
            assert getattr(service, store) == {}, store


ARN_BASE_list_types = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
)
SYSTEM_BROWSER_ARN = f"{ARN_BASE_list_types}:browser/aws.browser.v1"
CUSTOM_BROWSER_ARN = f"{ARN_BASE_list_types}:browser/custom-browser-abc123"
SYSTEM_INTERPRETER_ARN = (
    f"{ARN_BASE_list_types}:code-interpreter/aws.codeinterpreter.v1"
)
CUSTOM_INTERPRETER_ARN = (
    f"{ARN_BASE_list_types}:code-interpreter/custom-interpreter-abc123"
)


def _type_sensitive_mock(requested):
    """Build a `_make_api_call` replacement that records each `type` into `requested`.

    Returns SYSTEM resources ONLY for type=SYSTEM, mirroring the measured API. Both type=CUSTOM and
    the no-argument default return the custom resources -- that default branch is the one a collector
    which forgot `type` lands on, and it is why omitting the argument loses the built-in without
    losing everything.
    """

    def _mock(self, operation_name, kwarg):
        """Answer ListBrowsers and ListCodeInterpreters differently per ``type`` argument."""
        if operation_name in ("ListBrowsers", "ListCodeInterpreters"):
            requested.setdefault(operation_name, []).append(kwarg.get("type"))

        if operation_name == "ListBrowsers":
            if kwarg.get("type") == "SYSTEM":
                return {
                    "browserSummaries": [
                        {
                            "browserArn": SYSTEM_BROWSER_ARN,
                            "browserId": "aws.browser.v1",
                            "name": "aws.browser.v1",
                        }
                    ]
                }
            return {
                "browserSummaries": [
                    {
                        "browserArn": CUSTOM_BROWSER_ARN,
                        "browserId": "custom-browser-abc123",
                        "name": "custom-browser",
                    }
                ]
            }

        if operation_name == "ListCodeInterpreters":
            if kwarg.get("type") == "SYSTEM":
                return {
                    "codeInterpreterSummaries": [
                        {
                            "codeInterpreterArn": SYSTEM_INTERPRETER_ARN,
                            "codeInterpreterId": "aws.codeinterpreter.v1",
                            "name": "aws.codeinterpreter.v1",
                        }
                    ]
                }
            return {
                "codeInterpreterSummaries": [
                    {
                        "codeInterpreterArn": CUSTOM_INTERPRETER_ARN,
                        "codeInterpreterId": "custom-interpreter-abc123",
                        "name": "custom-interpreter",
                    }
                ]
            }

        if operation_name == "GetBrowser":
            return {"networkConfiguration": {"networkMode": "PUBLIC"}}
        if operation_name == "GetCodeInterpreter":
            return {"networkConfiguration": {"networkMode": "SANDBOX"}}
        if operation_name == "GetTokenVault":
            return {"kmsConfiguration": {"keyType": "ServiceManagedKey"}}
        # Everything else the service lists is out of scope here. Answer with an empty page rather
        # than delegating to the real _make_api_call: delegation needs a module-level capture of the
        # original, which is exactly what makes this file unsafe under xdist.
        return {}

    return _mock


def _collect_list_types():
    """Run the collectors under the type-sensitive mock; return (service, requested types)."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

    requested: dict[str, list] = {}
    # Build the provider BEFORE the patch. set_mocked_aws_provider makes its own calls (STS and
    # friends) and this mock answers unknown operations with {} instead of delegating, so provider
    # setup inside the patch starves and every assertion fails for the wrong reason.
    provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_type_sensitive_mock(requested)
    ):
        service = BedrockAgentCore(provider)
    return service, requested


class Test_AgentCore_List_Type_Pagination:
    """Both enum values must be requested, and both results must reach the inventory."""

    @mock_aws
    def test_browsers_include_the_system_builtin_and_the_custom_one(self):
        """Both browser types reach the inventory, so the AWS built-in is not dropped."""
        ac, _ = _collect_list_types()
        # The assertion that fails when `type` is dropped: a collector using the default gets the
        # custom browser only, so the built-in is missing and the count is 1 rather than 2.
        assert SYSTEM_BROWSER_ARN in ac.browsers, (
            "the SYSTEM built-in browser is missing -- ListBrowsers was probably called without "
            "type=SYSTEM, which returns only the custom browsers"
        )
        assert CUSTOM_BROWSER_ARN in ac.browsers
        assert len(ac.browsers) == 2

    @mock_aws
    def test_browsers_request_both_enum_values_explicitly(self):
        """``type`` is passed explicitly; relying on the default omits the SYSTEM browser."""
        _, requested = _collect_list_types()
        seen = requested.get("ListBrowsers", [])
        assert set(seen) == {"SYSTEM", "CUSTOM"}, (
            f"expected both enum values to be requested, saw {seen!r}; "
            "None means the default was relied on"
        )
        assert None not in seen

    @mock_aws
    def test_code_interpreters_include_the_system_builtin_and_the_custom_one(self):
        """Both interpreter types reach the inventory, including ``aws.codeinterpreter.v1``."""
        ac, _ = _collect_list_types()
        assert SYSTEM_INTERPRETER_ARN in ac.code_interpreters, (
            "the SYSTEM built-in code interpreter is missing -- ListCodeInterpreters was probably "
            "called without type=SYSTEM"
        )
        assert CUSTOM_INTERPRETER_ARN in ac.code_interpreters
        assert len(ac.code_interpreters) == 2

    @mock_aws
    def test_code_interpreters_request_both_enum_values_explicitly(self):
        """``type`` is passed explicitly for interpreters too, for the same measured reason."""
        _, requested = _collect_list_types()
        seen = requested.get("ListCodeInterpreters", [])
        assert set(seen) == {"SYSTEM", "CUSTOM"}, (
            f"expected both enum values to be requested, saw {seen!r}; "
            "None means the default was relied on"
        )
        assert None not in seen


GATEWAY_ARN_targets = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-abc123"
OTHER_GATEWAY_ARN_targets = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-def456"


def _mock_targets(
    targets=None, fail_targets_for=None, code="AccessDeniedException", gateways=None
):
    """Build a ``_make_api_call`` replacement for the gateway/target paths.

    ``targets`` maps a gatewayIdentifier to the target summaries ListGatewayTargets returns for it.
    ``fail_targets_for`` names a gatewayIdentifier whose ListGatewayTargets raises, so a failure can
    be aimed at one gateway while another succeeds.
    """
    gateways = (
        gateways if gateways is not None else [{"gatewayId": "gw-abc123", "name": "gw"}]
    )
    targets = targets or {}

    def _call(self, operation_name, kwarg):
        """Answer the gateway and target operations; empty for everything else."""
        if operation_name == "ListGateways":
            return {"items": gateways}
        if operation_name == "ListGatewayTargets":
            ident = kwarg.get("gatewayIdentifier")
            if fail_targets_for is not None and ident == fail_targets_for:
                raise ClientError(
                    {"Error": {"Code": code, "Message": "denied"}}, operation_name
                )
            return {"items": targets.get(ident, [])}
        if operation_name == "GetGatewayTarget":
            return {
                "credentialProviderConfigurations": [
                    {"credentialProviderType": "OAUTH"},
                    {"credentialProviderType": "API_KEY"},
                    {"somethingElse": "no type key, must be dropped"},
                ],
                "targetConfiguration": {
                    "mcp": {"lambda": {"lambdaArn": "arn:aws:lambda:::f"}}
                },
            }
        if operation_name == "GetGateway":
            return {"authorizerType": "CUSTOM_JWT"}
        # Everything else the constructor lists: answer empty rather than delegating to the real
        # _make_api_call, which would need a module-level capture.
        return {
            "ListMemories": {"memories": []},
            "ListAgentRuntimes": {"agentRuntimes": []},
            "ListBrowsers": {"browserSummaries": []},
            "ListCodeInterpreters": {"codeInterpreterSummaries": []},
            "GetTokenVault": {"tokenVaultId": "default"},
        }.get(operation_name, {})

    return _call


def _collect_targets(call, audit_resources=None):
    """Run the collectors under ``call``; return the service."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

    # Built BEFORE the patch: set_mocked_aws_provider makes its own STS calls, and this mock answers
    # unknown operations with {} instead of delegating, so provider setup inside the patch starves.
    provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    if audit_resources is not None:
        # AwsProvider.audit_resources is a read-only property over _audit_resources, and
        # set_mocked_aws_provider takes no argument for it.
        provider._audit_resources = audit_resources
    with mock.patch("botocore.client.BaseClient._make_api_call", new=call):
        return BedrockAgentCore(provider)


class Test_AgentCore_Gateway_Targets:
    @mock_aws
    def test_targets_are_collected_under_a_synthetic_arn(self):
        """A target is keyed by ``{gateway.arn}/target/{id}`` because AWS exposes no ARN for it."""
        ac = _collect_targets(
            _mock_targets(targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]})
        )
        expected = f"{GATEWAY_ARN_targets}/target/t-1"
        assert (
            expected in ac.gateway_targets
        ), f"expected a synthetic target ARN {expected!r}, got {list(ac.gateway_targets)!r}"
        target = ac.gateway_targets[expected]
        assert target.id == "t-1"
        assert target.name == "first"
        assert target.gateway_id == "gw-abc123"
        assert target.gateway_name == "gw"
        assert target.region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_a_successful_listing_marks_the_gateway_listed(self):
        """``targets_listed`` is what separates "this gateway has none" from "could not read"."""
        ac = _collect_targets(_mock_targets(targets={"gw-abc123": []}))
        gateway = ac.gateways[GATEWAY_ARN_targets]
        # The distinction this flag exists for: no targets AND listed means the gateway genuinely
        # has none, which a check may report on. Without it, "none" and "unreadable" look identical.
        assert gateway.targets_listed is True
        assert gateway.targets_error is None
        assert ac.gateway_targets == {}

    @mock_aws
    def test_get_gateway_target_enriches_and_drops_untyped_providers(self):
        """Enrichment fills the credential provider types, dropping entries with no type."""
        ac = _collect_targets(
            _mock_targets(targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]})
        )
        target = ac.gateway_targets[f"{GATEWAY_ARN_targets}/target/t-1"]
        assert target.detail_retrieved is True
        # The third configuration carries no credentialProviderType and must not appear as None.
        assert target.credential_provider_types == ["OAUTH", "API_KEY"]
        assert target.target_configuration == {
            "mcp": {"lambda": {"lambdaArn": "arn:aws:lambda:::f"}}
        }

    @mock_aws
    def test_a_denied_listing_is_recorded_on_the_gateway_not_the_region(self):
        """A target-listing failure belongs on the gateway, never in a Region-keyed store."""
        ac = _collect_targets(_mock_targets(fail_targets_for="gw-abc123"))
        gateway = ac.gateways[GATEWAY_ARN_targets]
        assert gateway.targets_error == "AccessDeniedException"
        assert gateway.targets_listed is False
        # The gateway itself must survive: losing it would turn an unreadable target list into an
        # absent gateway, which no check could report as unknown.
        assert GATEWAY_ARN_targets in ac.gateways
        assert ac.gateway_targets == {}
        # And it must NOT leak into a Region-keyed store. Targets are per gateway, so recording the
        # Region would mark every other gateway in it unknown too.
        assert ac.gateways_scan_errors == {}

    @mock_aws
    def test_one_gateways_failure_does_not_mask_anothers_targets(self):
        """Per-gateway granularity: one unreadable target list leaves the other gateway intact."""
        ac = _collect_targets(
            _mock_targets(
                gateways=[
                    {"gatewayId": "gw-abc123", "name": "gw"},
                    {"gatewayId": "gw-def456", "name": "other"},
                ],
                targets={"gw-def456": [{"targetId": "t-9", "name": "ninth"}]},
                fail_targets_for="gw-abc123",
            )
        )
        failed, ok = (
            ac.gateways[GATEWAY_ARN_targets],
            ac.gateways[OTHER_GATEWAY_ARN_targets],
        )
        assert failed.targets_error == "AccessDeniedException"
        assert failed.targets_listed is False
        assert ok.targets_error is None
        assert ok.targets_listed is True
        assert f"{OTHER_GATEWAY_ARN_targets}/target/t-9" in ac.gateway_targets
        assert len(ac.gateway_targets) == 1

    @mock_aws
    def test_a_target_without_an_id_is_skipped(self):
        """An empty id would build a colliding ARN, so such targets are dropped."""
        ac = _collect_targets(
            _mock_targets(
                targets={
                    "gw-abc123": [
                        {"targetId": "", "name": "no id"},
                        {"name": "id absent entirely"},
                        {"targetId": "t-1", "name": "keeps"},
                    ]
                }
            )
        )
        # An empty id would build the ARN "<gateway>/target/" and collide with any other id-less
        # target, silently collapsing them into one resource.
        assert list(ac.gateway_targets) == [f"{GATEWAY_ARN_targets}/target/t-1"]

    @mock_aws
    def test_targets_survive_a_resource_arn_scope_that_matches_the_gateway(self):
        """Targets are deliberately not filtered against ``audit_resources``; the ARN is synthetic."""
        ac = _collect_targets(
            _mock_targets(
                targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]}
            ),
            audit_resources=[GATEWAY_ARN_targets],
        )
        # Deliberate: the parent gateway was already filtered on its own ARN, and the target ARN is
        # synthetic, so filtering targets against audit_resources would drop every target of an
        # in-scope gateway. This asserts the collector does not do that.
        assert f"{GATEWAY_ARN_targets}/target/t-1" in ac.gateway_targets


class Test_AgentCore_Browser_Recording_Unknown:
    """An empty ``recording`` block must stay unknown rather than becoming a definite False."""

    @staticmethod
    def _browser_with(recording):
        """Build a mock answering GetBrowser with the given ``recording`` value.

        Args:
            recording: What GetBrowser should return under ``recording``; omit the key entirely by
                passing the sentinel string ``"omit"``.
        """

        def _call(self, operation_name, kwarg):
            """List one custom browser, then answer GetBrowser with the value under test."""
            if operation_name == "ListBrowsers":
                if kwarg.get("type") == "SYSTEM":
                    return {"browserSummaries": []}
                return {
                    "browserSummaries": [
                        {
                            "browserArn": f"{GATEWAY_ARN_targets.rsplit(':', 1)[0]}:browser/b-1",
                            "browserId": "b-1",
                            "name": "custom",
                        }
                    ]
                }
            if operation_name == "GetBrowser":
                info = {"networkConfiguration": {"networkMode": "PUBLIC"}}
                if recording != "omit":
                    info["recording"] = recording
                return info
            return {}

        return _call

    @mock_aws
    def test_an_empty_recording_block_leaves_the_state_unknown(self):
        """``"recording": {}`` omits ``enabled``, so the state is unknown, not disabled.

        ``RecordingConfig.enabled`` is optional at the pinned botocore, so an empty block is a legal
        response. Reading it as False would let a check report a definite verdict about a browser whose
        recording state the API never stated.
        """
        ac = _collect_targets(self._browser_with({}))
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is None, (
            "an empty recording block must stay unknown; got "
            f"{browser.recording_enabled!r}"
        )

    @mock_aws
    def test_no_recording_block_at_all_is_disabled(self):
        """The negative control: an absent block really does mean recording is off."""
        ac = _collect_targets(self._browser_with("omit"))
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is False

    @mock_aws
    def test_an_explicit_enabled_flag_is_honoured(self):
        """And a stated value is read through unchanged."""
        for stated in (True, False):
            ac = _collect_targets(self._browser_with({"enabled": stated}))
            browser = next(iter(ac.browsers.values()))
            assert browser.recording_enabled is stated, stated


MEMORY_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd1234"


class Test_AgentCore_Memory_Arn_Only_Summary:
    """A MemorySummary carrying an ARN but no id must still yield a usable identifier."""

    @staticmethod
    def _memory_listing(summary):
        """Build a mock whose ListMemories returns the one summary under test.

        Args:
            summary: The MemorySummary dict to return.
        """

        def _call(self, operation_name, kwarg):
            """Return the summary for ListMemories and record what GetMemory was asked for."""
            if operation_name == "ListMemories":
                return {"memories": [summary]}
            if operation_name == "GetMemory":
                # A real GetMemory rejects an empty memoryId outright: at the pin the member is
                # min=12 with a pattern, so an empty value never reaches the service.
                assert kwarg.get(
                    "memoryId"
                ), "GetMemory was called with an empty memoryId, which the API rejects"
                # NESTED under "memory", which is what _get_memory reads. A root-level
                # encryptionKeyArn is silently ignored, so asserting only detail_retrieved -- which
                # is set either way -- would pass without the enrichment ever landing.
                return {"memory": {"encryptionKeyArn": MEMORY_KEY_ARN}}
            return {}

        return _call

    @mock_aws
    def test_an_arn_only_summary_recovers_the_id_from_the_arn(self):
        """`id` is optional on MemorySummary, so derive it rather than storing an empty string."""
        arn = (
            f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
            ":memory/mem-abcdefghij"
        )
        ac = _collect_targets(self._memory_listing({"arn": arn}))
        assert arn in ac.memories
        assert (
            ac.memories[arn].id == "mem-abcdefghij"
        ), f"the id must come from the ARN's last segment; got {ac.memories[arn].id!r}"
        # And the enrichment must actually have LANDED, which the empty id prevented. Asserting
        # detail_retrieved alone is not enough: it is set whenever GetMemory returns at all, so a
        # mapped field has to be checked or the case passes on a response shape the collector
        # ignores.
        assert ac.memories[arn].detail_retrieved is True
        assert ac.memories[arn].encryption_key_arn == MEMORY_KEY_ARN

    @mock_aws
    def test_an_id_only_summary_still_builds_the_arn(self):
        """The negative control for the existing fallback in the other direction."""
        ac = _collect_targets(self._memory_listing({"id": "mem-abcdefghij"}))
        assert len(ac.memories) == 1
        arn = next(iter(ac.memories))
        assert arn.endswith(":memory/mem-abcdefghij")
        assert ac.memories[arn].id == "mem-abcdefghij"


LISTING_TO_STORE_unexpected = {
    "ListMemories": "memories_scan_errors",
    "ListGateways": "gateways_scan_errors",
    "ListAgentRuntimes": "agent_runtimes_scan_errors",
    "ListCodeInterpreters": "code_interpreters_scan_errors",
    "ListBrowsers": "browsers_scan_errors",
    "GetTokenVault": "token_vaults_scan_errors",
}
GATEWAY_ARN_unexpected = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-abc123"


def _raise_non_client_error(exc):
    """Build a `_make_api_call` replacement raising `exc` for every AgentCore listing.

    Deliberately NOT a ClientError: the point is the `except Exception` fallback, which a
    ClientError would never reach.
    """

    def _call(self, operation_name, kwarg):
        """Raise the given non-ClientError for every listing the constructor performs."""
        if operation_name in LISTING_TO_STORE_unexpected:
            raise exc
        return {}

    return _call


def _collect_unexpected(call):
    """Build the provider outside the patch, then run the collectors under ``call``."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

    # Provider built BEFORE the patch: this mock answers unknown operations with {} rather than
    # delegating, so provider setup inside the patch would starve.
    provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch("botocore.client.BaseClient._make_api_call", new=call):
        return BedrockAgentCore(provider)


class Test_AgentCore_Unexpected_Listing_Errors:
    @mock_aws
    def test_a_non_client_error_is_recorded_by_class_name(self):
        """The generic handler records the exception class, not an API error code."""
        ac = _collect_unexpected(
            _raise_non_client_error(ConnectionResetError("peer went away"))
        )
        for op, store in LISTING_TO_STORE_unexpected.items():
            assert getattr(ac, store) == {
                AWS_REGION_US_EAST_1: "ConnectionResetError"
            }, (
                f"{op} failed with a non-ClientError and {store} did not record it; an empty store "
                f"is indistinguishable from a Region that genuinely holds no resources"
            )

    @mock_aws
    def test_the_inventory_stays_empty_rather_than_partially_populated(self):
        """A failed listing must leave nothing behind that reads as a complete inventory."""
        ac = _collect_unexpected(
            _raise_non_client_error(ConnectionResetError("peer went away"))
        )
        # Every listing failed, so nothing may be reported as present. A collector that appended
        # before the raise would leave a half-built inventory that reads as complete.
        assert ac.memories == {}
        assert ac.gateways == {}
        assert ac.gateway_targets == {}
        assert ac.agent_runtimes == {}
        assert ac.browsers == {}
        assert ac.code_interpreters == {}
        assert ac.token_vaults == {}

    @mock_aws
    def test_a_different_exception_type_records_that_type(self):
        """A second exception type proves the class name is read from the error, not hardcoded.

        Guards against the class name being hardcoded or the store being written from the wrong
        variable -- both of which the single-exception test above would pass.
        """
        ac = _collect_unexpected(_raise_non_client_error(TimeoutError("too slow")))
        for store in LISTING_TO_STORE_unexpected.values():
            assert getattr(ac, store) == {AWS_REGION_US_EAST_1: "TimeoutError"}, store

    @mock_aws
    def test_a_gateway_target_listing_failure_is_recorded_on_the_gateway(self):
        """The gateway-target collector's generic handler writes to the gateway, not a Region store."""

        def _call(self, operation_name, kwarg):
            """List the gateway successfully, then fail its target listing with a transport error."""
            if operation_name == "ListGateways":
                return {"items": [{"gatewayId": "gw-abc123", "name": "gw"}]}
            if operation_name == "ListGatewayTargets":
                raise ConnectionResetError("peer went away")
            if operation_name == "GetGateway":
                return {"authorizerType": "CUSTOM_JWT"}
            return {}

        ac = _collect_unexpected(_call)
        gateway = ac.gateways[GATEWAY_ARN_unexpected]
        assert gateway.targets_error == "ConnectionResetError"
        assert gateway.targets_listed is False
        # And it must not be promoted to a Region-wide error: only this gateway's targets are unknown.
        assert ac.gateways_scan_errors == {}

    @mock_aws
    def test_a_failed_enrichment_leaves_detail_retrieved_false(self):
        """A resource that listed but could not be described is UNKNOWN, not "configured this way".

        The per-resource `_get_*` methods have their own generic handler, and it writes no error store
        -- it only logs. What it must do is leave `detail_retrieved` False, because that flag is the
        whole basis on which the checks distinguish "the field is absent" from "the field could not be
        read". Flip it to True on failure and every check reading an enrichment field would report a
        confident verdict about a resource it never described.
        """

        def _call(self, operation_name, kwarg):
            """List resources successfully, then fail every enrichment call."""
            if operation_name == "ListGateways":
                return {"items": [{"gatewayId": "gw-abc123", "name": "gw"}]}
            if operation_name == "ListGatewayTargets":
                return {"items": [{"targetId": "t-1", "name": "first"}]}
            if operation_name == "ListMemories":
                return {
                    "memories": [
                        {
                            "arn": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}"
                            f":{AWS_ACCOUNT_NUMBER}:memory/mem-1",
                            "id": "mem-1",
                        }
                    ]
                }
            # Every enrichment call fails with a non-ClientError.
            if operation_name.startswith("Get"):
                raise ConnectionResetError("peer went away")
            return {}

        ac = _collect_unexpected(_call)
        assert ac.gateways[GATEWAY_ARN_unexpected].detail_retrieved is False
        assert (
            ac.gateway_targets[f"{GATEWAY_ARN_unexpected}/target/t-1"].detail_retrieved
            is False
        )
        assert all(m.detail_retrieved is False for m in ac.memories.values())
        # The resources themselves must survive -- a failed enrichment is not a failed listing, so
        # dropping them would turn "described nothing" into "found nothing".
        assert GATEWAY_ARN_unexpected in ac.gateways
        assert len(ac.memories) == 1
