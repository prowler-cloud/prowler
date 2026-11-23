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

GUARDRAIL_ID = "test-guardrail-id"
GUARDRAIL_NAME = "test-guardrail"
GUARDRAIL_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/{GUARDRAIL_ID}"

# Operations the Bedrock constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "GetModelInvocationLoggingConfiguration",
    "ListTagsForResource",
    "ListCustomModels",
)


def _guardrail_mock(grounding_policy=None, fail_get=False):
    """Build a _make_api_call replacement returning one guardrail."""

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListGuardrails":
            return {
                "guardrails": [
                    {
                        "id": GUARDRAIL_ID,
                        "name": GUARDRAIL_NAME,
                        "arn": GUARDRAIL_ARN,
                        "status": "READY",
                    }
                ]
            }
        if operation_name == "GetGuardrail":
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            response = {
                "guardrailId": GUARDRAIL_ID,
                "guardrailArn": GUARDRAIL_ARN,
                "name": GUARDRAIL_NAME,
                "status": "READY",
            }
            if grounding_policy is not None:
                response["contextualGroundingPolicy"] = grounding_policy
            return response
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _filter(filter_type, threshold=0.75, action="BLOCK", enabled=True):
    """Build one contextual grounding filter; a None value omits that key.

    Both action and enabled are optional members of the API shape, so omitting
    either has to be expressible here to test the unknown paths.
    """
    filter = {"type": filter_type, "threshold": threshold}
    if action is not None:
        filter["action"] = action
    if enabled is not None:
        filter["enabled"] = enabled
    return filter


_mock_action_absent = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", action=None),
            _filter("RELEVANCE", action=None),
        ]
    }
)
_mock_action_absent_one_filter = _guardrail_mock(
    {"filters": [_filter("GROUNDING", action=None), _filter("RELEVANCE")]}
)
_mock_action_absent_with_zero_threshold = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", action=None, threshold=0.0),
            _filter("RELEVANCE"),
        ]
    }
)


_mock_both_blocking = _guardrail_mock(
    {"filters": [_filter("GROUNDING"), _filter("RELEVANCE")]}
)
_mock_no_policy = _guardrail_mock(None)
_mock_empty_filters = _guardrail_mock({"filters": []})
_mock_missing_relevance = _guardrail_mock({"filters": [_filter("GROUNDING")]})
_mock_missing_grounding = _guardrail_mock({"filters": [_filter("RELEVANCE")]})
# A policy carrying only an unrecognised filter type: the policy exists, so it is
# not the "no policy" case, yet both required types are absent at once.
_mock_missing_both = _guardrail_mock({"filters": [_filter("UNKNOWN_TYPE")]})
_mock_action_none = _guardrail_mock(
    {"filters": [_filter("GROUNDING", action="NONE"), _filter("RELEVANCE")]}
)
_mock_zero_threshold = _guardrail_mock(
    {"filters": [_filter("GROUNDING"), _filter("RELEVANCE", threshold=0.0)]}
)
_mock_disabled = _guardrail_mock(
    {"filters": [_filter("GROUNDING", enabled=False), _filter("RELEVANCE")]}
)
_mock_both_disabled = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", enabled=False),
            _filter("RELEVANCE", enabled=False),
        ]
    }
)
_mock_disabled_and_action_none = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", enabled=False, action="NONE"),
            _filter("RELEVANCE"),
        ]
    }
)
_mock_enabled_absent = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", enabled=None),
            _filter("RELEVANCE", enabled=None),
        ]
    }
)
_mock_enabled_absent_one_filter = _guardrail_mock(
    {"filters": [_filter("GROUNDING", enabled=None), _filter("RELEVANCE")]}
)
_mock_enabled_absent_with_action_none = _guardrail_mock(
    {
        "filters": [
            _filter("GROUNDING", enabled=None, action="NONE"),
            _filter("RELEVANCE", enabled=None),
        ]
    }
)
_mock_unreadable = _guardrail_mock(fail_get=True)


def _mock_empty(self, operation_name, kwarg):
    """No guardrails at all."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListGuardrails":
        return {"guardrails": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_list_guardrails_denied(self, operation_name, kwarg):
    """ListGuardrails is denied, so the region's guardrails are unknown."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListGuardrails":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListGuardrails":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_guardrail_contextual_grounding_filter_enabled:
    """Unit tests for the bedrock_guardrail_contextual_grounding_filter_enabled check."""

    def _run(self):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_guardrail_contextual_grounding_filter_enabled.bedrock_guardrail_contextual_grounding_filter_enabled.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_contextual_grounding_filter_enabled.bedrock_guardrail_contextual_grounding_filter_enabled import (
                bedrock_guardrail_contextual_grounding_filter_enabled,
            )

            return bedrock_guardrail_contextual_grounding_filter_enabled().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_both_blocking)
    @mock_aws
    def test_both_filters_blocking_passes(self):
        """Both filter types enabled and blocking above a zero threshold is compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == GUARDRAIL_ID
        assert result[0].resource_arn == GUARDRAIL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert "blocks ungrounded and irrelevant responses" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_no_policy)
    @mock_aws
    def test_no_grounding_policy_fails(self):
        """No contextual grounding policy at all means nothing is ever detected."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no contextual grounding policy" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty_filters)
    @mock_aws
    def test_empty_filter_list_fails(self):
        """A policy present but carrying no filters is equivalent to no policy."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no contextual grounding policy" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_missing_relevance
    )
    @mock_aws
    def test_missing_relevance_filter_fails(self):
        """A GROUNDING filter alone leaves irrelevant answers unchecked."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "missing the RELEVANCE filter" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_missing_grounding
    )
    @mock_aws
    def test_missing_grounding_filter_fails(self):
        """A RELEVANCE filter alone leaves unsupported answers unchecked."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "missing the GROUNDING filter" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_missing_both)
    @mock_aws
    def test_missing_both_filters_fails_with_plural_wording(self):
        """Both required types can be absent at once, so the nouns must agree.

        The message lists the missing types, so hard-coding "filter" and "that
        class" would read "missing the GROUNDING, RELEVANCE filter ... leaving
        that class of ungrounded response unchecked".
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "missing the GROUNDING, RELEVANCE filters" in result[0].status_extended
        assert "leaving those classes of ungrounded response" in (
            result[0].status_extended
        )
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_action_none)
    @mock_aws
    def test_action_none_fails(self):
        """Action NONE scores and reports without blocking, so it must FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "GROUNDING filter uses action NONE" in result[0].status_extended
        assert "without blocking" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_zero_threshold)
    @mock_aws
    def test_zero_threshold_fails(self):
        """A threshold of 0 can never be tripped, so the filter blocks nothing."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "RELEVANCE filter has a threshold of 0" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_disabled)
    @mock_aws
    def test_disabled_filter_fails(self):
        """enabled: false runs no evaluation, so BLOCK and a real threshold are inert."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "GROUNDING filter is disabled" in result[0].status_extended
        assert "its evaluation never runs" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_both_disabled)
    @mock_aws
    def test_both_filters_disabled_fails(self):
        """Both filters disabled reports both, not just the first."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "GROUNDING filter is disabled" in result[0].status_extended
        assert "RELEVANCE filter is disabled" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_disabled_and_action_none
    )
    @mock_aws
    def test_disabled_reported_ahead_of_action(self):
        """Disabled is the operative defect: the action is never reached."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "GROUNDING filter is disabled" in result[0].status_extended
        assert "action NONE" not in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_enabled_absent)
    @mock_aws
    def test_absent_enabled_is_manual_not_pass(self):
        """enabled is optional with no documented default, so absent is unknown."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "GROUNDING filter omits enabled, RELEVANCE filter omits enabled"
            in result[0].status_extended
        )
        # Two unknown filters take the plural subject.
        assert "so whether they block is unknown" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_enabled_absent_one_filter
    )
    @mock_aws
    def test_absent_enabled_on_one_filter_is_manual(self):
        """One filter omitting enabled is enough to make the answer unknown."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "GROUNDING filter omits enabled" in result[0].status_extended
        # action was present, so it must not be reported as missing.
        assert "omits action" not in result[0].status_extended
        assert "RELEVANCE" not in result[0].status_extended
        assert "so whether it blocks is unknown" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_action_absent)
    @mock_aws
    def test_absent_action_is_manual_not_fail(self):
        """action is optional with no documented default, so omitting it is unknown.

        Treating an absent action as NONE would assert a misconfiguration the
        response never stated, and would print the literal None as if it were an
        AWS enum value. It is reported the same way as an absent enabled.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "None" not in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_action_absent_one_filter
    )
    @mock_aws
    def test_absent_action_on_one_filter_is_manual(self):
        """One filter omitting action is enough to make the answer unknown."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "GROUNDING filter omits action" in result[0].status_extended
        # enabled was present, so it must not be reported as missing.
        assert "omits enabled" not in result[0].status_extended
        assert "RELEVANCE" not in result[0].status_extended
        assert "so whether it blocks is unknown" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_action_absent_with_zero_threshold,
    )
    @mock_aws
    def test_absent_action_does_not_mask_a_definite_defect(self):
        """An unknown action must not downgrade a real threshold defect to MANUAL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "threshold" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_enabled_absent_with_action_none,
    )
    @mock_aws
    def test_absent_enabled_does_not_mask_a_definite_defect(self):
        """An unknown enabled must not downgrade a real action defect to MANUAL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "GROUNDING filter uses action NONE" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_pass(self):
        """A failed GetGuardrail must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_list_guardrails_denied
    )
    @mock_aws
    def test_list_guardrails_denied_is_manual_not_silence(self):
        """A denied ListGuardrails must report MANUAL for the region, not vanish.

        Without this the Region is indistinguishable from one holding no
        guardrails, which is the same silent-inventory gap the sibling checks
        report against custom-model/unknown and knowledge-base/unknown.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "guardrail/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/unknown"
        )
        assert "could not be listed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")
