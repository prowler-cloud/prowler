"""Tests for how BedrockAgentCore reports an inventory it could not read.

A check can only be as complete as the inventory behind it. If a listing fails
and the service records nothing, the resulting empty collection is
indistinguishable from an account that genuinely holds no resources, and every
check silently reports PASS-by-omission for the whole Region. These tests pin the
behaviours that prevent that: a failed listing is recorded per collector, one
collector's success cannot mask another's failure, and a Region the service does
not serve is not recorded at all.
"""

from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


# Every listing the BedrockAgentCore constructor performs, paired with the error
# store that must record its failure.
LISTING_TO_STORE = {
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
        if operation_name in LISTING_TO_STORE:
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
        if operation_name == failing_operation:
            raise ClientError(
                {"Error": {"Code": code, "Message": "denied"}}, operation_name
            )
        if operation_name in empty:
            return empty[operation_name]
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _build_service():
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
            service = _build_service()

        for store in LISTING_TO_STORE.values():
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
            service = _build_service()

        for store in LISTING_TO_STORE.values():
            assert getattr(service, store) == {}, store

    @mock_aws
    def test_absent_token_vault_is_not_recorded_as_an_error(self):
        """An account with no token vault in a Region is "none", not "unknown"."""
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_all_calls_raise("ResourceNotFoundException"),
        ):
            service = _build_service()

        assert service.token_vaults_scan_errors == {}
        assert service.token_vaults == {}

    @mock_aws
    def test_one_failed_listing_does_not_mask_the_others(self):
        """Stores are independent, so a success cannot hide a sibling's failure.

        A single shared store would be written by whichever collector ran last,
        so a check reading it could not tell which inventory is incomplete.
        """
        for failing_operation, store in LISTING_TO_STORE.items():
            with mock.patch(
                "botocore.client.BaseClient._make_api_call",
                new=_one_call_raises(failing_operation),
            ):
                service = _build_service()

            assert getattr(service, store) == {
                AWS_REGION_US_EAST_1: "AccessDeniedException"
            }, failing_operation
            for other_store in LISTING_TO_STORE.values():
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
            service = _build_service()

        for store in LISTING_TO_STORE.values():
            assert getattr(service, store) == {}, store
