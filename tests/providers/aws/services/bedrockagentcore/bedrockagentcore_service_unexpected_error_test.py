"""A listing that fails with something other than a ClientError must still be recorded.

WHY THIS FILE EXISTS. Each AgentCore collector has two handlers: `except ClientError`, which reads
the API error code out of the response and deliberately swallows `ValidationException`, and a generic
`except Exception`, which records `error.__class__.__name__` instead. `..._inventory_test.py` drives
only the first -- every one of its mocks raises `ClientError` -- so the generic handler in each
collector was unexecuted. Measured: 40 of the 554 lines this service file adds were uncovered, and
almost all of them were those handlers.

That gap matters more than a coverage number suggests, because the two handlers record DIFFERENT
values. The ClientError path stores an API error code (`AccessDeniedException`); the generic path
stores a Python class name (`ConnectionResetError`). A check reading the store to decide between
"unknown" and "definitely none" behaves the same either way, but a collector that forgot to populate
the store on the generic path would silently turn a transport failure into "this Region has no
resources" -- a false PASS-by-omission, which is the exact failure the per-listing stores exist to
prevent. Nothing would have caught it.

`ValidationException` handling is the reason these must be tested separately rather than folded into
the existing file: the ClientError path treats it as a definite negative and records nothing, so a
test asserting "every failure is recorded" can only be written against the generic path.

NO MODULE-LEVEL STATE. The mock is built per test and answers every operation itself rather than
delegating to a captured `_make_api_call`, which is unsafe under `pytest -n auto` because import
order varies across workers.
"""

from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Every listing the constructor performs, paired with the store its generic handler must populate.
LISTING_TO_STORE = {
    "ListMemories": "memories_scan_errors",
    "ListGateways": "gateways_scan_errors",
    "ListAgentRuntimes": "agent_runtimes_scan_errors",
    "ListCodeInterpreters": "code_interpreters_scan_errors",
    "ListBrowsers": "browsers_scan_errors",
    "GetTokenVault": "token_vaults_scan_errors",
}

GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/gw-abc123"


def _raise_non_client_error(exc):
    """Build a `_make_api_call` replacement raising `exc` for every AgentCore listing.

    Deliberately NOT a ClientError: the point is the `except Exception` fallback, which a
    ClientError would never reach.
    """

    def _call(self, operation_name, kwarg):
        """Raise the given non-ClientError for every listing the constructor performs."""
        if operation_name in LISTING_TO_STORE:
            raise exc
        return {}

    return _call


def _collect(call):
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
        ac = _collect(_raise_non_client_error(ConnectionResetError("peer went away")))
        for op, store in LISTING_TO_STORE.items():
            assert getattr(ac, store) == {
                AWS_REGION_US_EAST_1: "ConnectionResetError"
            }, (
                f"{op} failed with a non-ClientError and {store} did not record it; an empty store "
                f"is indistinguishable from a Region that genuinely holds no resources"
            )

    @mock_aws
    def test_the_inventory_stays_empty_rather_than_partially_populated(self):
        """A failed listing must leave nothing behind that reads as a complete inventory."""
        ac = _collect(_raise_non_client_error(ConnectionResetError("peer went away")))
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
        ac = _collect(_raise_non_client_error(TimeoutError("too slow")))
        for store in LISTING_TO_STORE.values():
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

        ac = _collect(_call)
        gateway = ac.gateways[GATEWAY_ARN]
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

        ac = _collect(_call)
        assert ac.gateways[GATEWAY_ARN].detail_retrieved is False
        assert ac.gateway_targets[f"{GATEWAY_ARN}/target/t-1"].detail_retrieved is False
        assert all(m.detail_retrieved is False for m in ac.memories.values())
        # The resources themselves must survive -- a failed enrichment is not a failed listing, so
        # dropping them would turn "described nothing" into "found nothing".
        assert GATEWAY_ARN in ac.gateways
        assert len(ac.memories) == 1
