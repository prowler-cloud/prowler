"""Tests for the AgentCore gateway-target collector.

WHY THIS FILE EXISTS. The gateway-target collector shipped with no test at all. It is the one
AgentCore listing with no consumer in the collector PR -- the check that reads it arrives in a later
PR -- and that is exactly why it needs pinning here: an untested collector with no caller can be
broken for a whole release cycle without a single failure, and the check that finally reads it
inherits the bug rather than causing it.

It is also the only listing whose failure is NOT recorded in a Region-keyed ``*_scan_errors`` store.
Targets are listed per gateway, so the error belongs on the gateway (``targets_error``,
``targets_listed``) rather than against the Region: one gateway whose targets cannot be listed must
not mark the whole Region unknown, and must not mark the *other* gateways unknown either. That
granularity is the substance of these tests.

Two further behaviours are deliberate and would otherwise look like bugs to a later reader:

    * the target ARN is SYNTHETIC (``{gateway.arn}/target/{target_id}``) because AWS exposes none;
    * so the collector does NOT filter targets against ``audit_resources``. A synthetic ARN could
      never match a user-supplied ``--resource-arn``, and filtering on it would silently drop every
      target of an in-scope gateway.

NO MODULE-LEVEL STATE. The mock is built per test by a factory and answers every operation the
constructor touches rather than delegating to a captured ``_make_api_call``. A module-level capture
is unsafe under ``pytest -n auto``: import order varies across workers, so the captured function can
be another module's active mock.
"""

from unittest import mock

from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-abc123"
OTHER_GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-def456"


def _mock(
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


def _collect(call, audit_resources=None):
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
        ac = _collect(
            _mock(targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]})
        )
        expected = f"{GATEWAY_ARN}/target/t-1"
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
        ac = _collect(_mock(targets={"gw-abc123": []}))
        gateway = ac.gateways[GATEWAY_ARN]
        # The distinction this flag exists for: no targets AND listed means the gateway genuinely
        # has none, which a check may report on. Without it, "none" and "unreadable" look identical.
        assert gateway.targets_listed is True
        assert gateway.targets_error is None
        assert ac.gateway_targets == {}

    @mock_aws
    def test_get_gateway_target_enriches_and_drops_untyped_providers(self):
        """Enrichment fills the credential provider types, dropping entries with no type."""
        ac = _collect(
            _mock(targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]})
        )
        target = ac.gateway_targets[f"{GATEWAY_ARN}/target/t-1"]
        assert target.detail_retrieved is True
        # The third configuration carries no credentialProviderType and must not appear as None.
        assert target.credential_provider_types == ["OAUTH", "API_KEY"]
        assert target.target_configuration == {
            "mcp": {"lambda": {"lambdaArn": "arn:aws:lambda:::f"}}
        }

    @mock_aws
    def test_a_denied_listing_is_recorded_on_the_gateway_not_the_region(self):
        """A target-listing failure belongs on the gateway, never in a Region-keyed store."""
        ac = _collect(_mock(fail_targets_for="gw-abc123"))
        gateway = ac.gateways[GATEWAY_ARN]
        assert gateway.targets_error == "AccessDeniedException"
        assert gateway.targets_listed is False
        # The gateway itself must survive: losing it would turn an unreadable target list into an
        # absent gateway, which no check could report as unknown.
        assert GATEWAY_ARN in ac.gateways
        assert ac.gateway_targets == {}
        # And it must NOT leak into a Region-keyed store. Targets are per gateway, so recording the
        # Region would mark every other gateway in it unknown too.
        assert ac.gateways_scan_errors == {}

    @mock_aws
    def test_one_gateways_failure_does_not_mask_anothers_targets(self):
        """Per-gateway granularity: one unreadable target list leaves the other gateway intact."""
        ac = _collect(
            _mock(
                gateways=[
                    {"gatewayId": "gw-abc123", "name": "gw"},
                    {"gatewayId": "gw-def456", "name": "other"},
                ],
                targets={"gw-def456": [{"targetId": "t-9", "name": "ninth"}]},
                fail_targets_for="gw-abc123",
            )
        )
        failed, ok = ac.gateways[GATEWAY_ARN], ac.gateways[OTHER_GATEWAY_ARN]
        assert failed.targets_error == "AccessDeniedException"
        assert failed.targets_listed is False
        assert ok.targets_error is None
        assert ok.targets_listed is True
        assert f"{OTHER_GATEWAY_ARN}/target/t-9" in ac.gateway_targets
        assert len(ac.gateway_targets) == 1

    @mock_aws
    def test_a_target_without_an_id_is_skipped(self):
        """An empty id would build a colliding ARN, so such targets are dropped."""
        ac = _collect(
            _mock(
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
        assert list(ac.gateway_targets) == [f"{GATEWAY_ARN}/target/t-1"]

    @mock_aws
    def test_targets_survive_a_resource_arn_scope_that_matches_the_gateway(self):
        """Targets are deliberately not filtered against ``audit_resources``; the ARN is synthetic."""
        ac = _collect(
            _mock(targets={"gw-abc123": [{"targetId": "t-1", "name": "first"}]}),
            audit_resources=[GATEWAY_ARN],
        )
        # Deliberate: the parent gateway was already filtered on its own ARN, and the target ARN is
        # synthetic, so filtering targets against audit_resources would drop every target of an
        # in-scope gateway. This asserts the collector does not do that.
        assert f"{GATEWAY_ARN}/target/t-1" in ac.gateway_targets


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
                            "browserArn": f"{GATEWAY_ARN.rsplit(':', 1)[0]}:browser/b-1",
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
        ac = _collect(self._browser_with({}))
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is None, (
            "an empty recording block must stay unknown; got "
            f"{browser.recording_enabled!r}"
        )

    @mock_aws
    def test_no_recording_block_at_all_is_disabled(self):
        """The negative control: an absent block really does mean recording is off."""
        ac = _collect(self._browser_with("omit"))
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is False

    @mock_aws
    def test_an_explicit_enabled_flag_is_honoured(self):
        """And a stated value is read through unchanged."""
        for stated in (True, False):
            ac = _collect(self._browser_with({"enabled": stated}))
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
        ac = _collect(self._memory_listing({"arn": arn}))
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
        ac = _collect(self._memory_listing({"id": "mem-abcdefghij"}))
        assert len(ac.memories) == 1
        arn = next(iter(ac.memories))
        assert arn.endswith(":memory/mem-abcdefghij")
        assert ac.memories[arn].id == "mem-abcdefghij"
