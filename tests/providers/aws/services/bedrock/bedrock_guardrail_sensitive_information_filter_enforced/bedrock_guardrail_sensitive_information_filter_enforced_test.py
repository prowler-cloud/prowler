from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

CHECK_MODULE = (
    "prowler.providers.aws.services.bedrock."
    "bedrock_guardrail_sensitive_information_filter_enforced."
    "bedrock_guardrail_sensitive_information_filter_enforced"
)
GUARDRAIL_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id"
)


def _guardrail_detail(sensitive_information_policy=None):
    """Build a GetGuardrail response, omitting sensitiveInformationPolicy when None is passed.

    Omission is the point: the API leaves the key out entirely when no policy is configured, and a
    guardrail in that state is out of this check's scope. Passing None reproduces that state
    faithfully rather than sending an empty dict the API would never return.
    """
    detail = {
        "name": "test",
        "guardrailId": "test-id",
        "guardrailArn": GUARDRAIL_ARN,
        "status": "READY",
        "blockedInputMessaging": "Sorry, the model cannot answer this question.",
        "blockedOutputsMessaging": "Sorry, the model cannot answer this question.",
    }
    if sensitive_information_policy is not None:
        detail["sensitiveInformationPolicy"] = sensitive_information_policy
    return detail


def _api_call(sensitive_information_policy=None, get_guardrail_error=None):
    """Build a _make_api_call replacement returning one guardrail with the given policy."""

    def _mocked(self, operation_name, kwarg):
        """Serve ListGuardrails, GetGuardrail and ListTagsForResource; defer everything else.

        GetGuardrail raises when get_guardrail_error was supplied, which is how the
        detail-unreadable state is reproduced.
        """
        if operation_name == "ListGuardrails":
            return {
                "guardrails": [
                    {
                        "id": "test-id",
                        "arn": GUARDRAIL_ARN,
                        "status": "READY",
                        "name": "test",
                    }
                ]
            }
        if operation_name == "GetGuardrail":
            if get_guardrail_error is not None:
                raise get_guardrail_error
            return _guardrail_detail(sensitive_information_policy)
        if operation_name == "ListTagsForResource":
            return {"tags": []}
        return make_api_call(self, operation_name, kwarg)

    return _mocked


SECOND_GUARDRAIL_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/second-id"
)


def _api_call_two_guardrails(self, operation_name, kwarg):
    """One enforcing guardrail and one inert one, so a truncated loop cannot pass."""
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test",
                },
                {
                    "id": "second-id",
                    "arn": SECOND_GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "second",
                },
            ]
        }
    if operation_name == "GetGuardrail":
        if kwarg["guardrailIdentifier"] == "second-id":
            detail = _guardrail_detail(
                {"piiEntities": [{"type": "EMAIL", "action": "NONE"}]}
            )
            detail["name"] = "second"
            detail["guardrailId"] = "second-id"
            detail["guardrailArn"] = SECOND_GUARDRAIL_ARN
            return detail
        return _guardrail_detail(
            {"piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}]}
        )
    if operation_name == "ListTagsForResource":
        return {"tags": []}
    return make_api_call(self, operation_name, kwarg)


def _run_check(api_call, regions=None):
    """Execute the check against a Bedrock service built from the given _make_api_call stand-in.

    The service is constructed inside the patch so its collectors read the stand-in, then injected
    as the check's bedrock_client. Returns the list of reports the check produced.
    """
    from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

    aws_provider = set_mocked_aws_provider(regions or [AWS_REGION_US_EAST_1])

    with mock.patch("botocore.client.BaseClient._make_api_call", new=api_call):
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_sensitive_information_filter_enforced.bedrock_guardrail_sensitive_information_filter_enforced import (
                bedrock_guardrail_sensitive_information_filter_enforced,
            )

            check = bedrock_guardrail_sensitive_information_filter_enforced()
            return check.execute()


class Test_bedrock_guardrail_sensitive_information_filter_enforced:
    @mock_aws
    def test_no_guardrails(self):
        """An account with no guardrails in either audited Region must produce no findings at all.

        Not a PASS: there is no resource to make a claim about, and a synthesised PASS per Region
        would report enforcement on something that does not exist.
        """
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_sensitive_information_filter_enforced.bedrock_guardrail_sensitive_information_filter_enforced import (
                bedrock_guardrail_sensitive_information_filter_enforced,
            )

            check = bedrock_guardrail_sensitive_information_filter_enforced()
            assert check.execute() == []

    @mock_aws
    def test_guardrail_without_sensitive_information_policy_skipped(self):
        """A guardrail with no policy at all is the other check's subject, not this one's."""
        assert _run_check(_api_call(sensitive_information_policy=None)) == []

    @mock_aws
    def test_pii_entities_anonymize_passes(self):
        """Two PII entities both set to ANONYMIZE must PASS: masking stops the value leaving.

        Also pins the plural wording and the resource identity, so the PASS message and the
        guardrail it is attributed to are both asserted, not just the status.
        """
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {"type": "EMAIL", "action": "ANONYMIZE"},
                        {"type": "NAME", "action": "ANONYMIZE"},
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Bedrock Guardrail test blocks or masks all 2 configured sensitive information entries on the output path."
        )
        assert result[0].resource_id == "test-id"
        assert result[0].resource_arn == GUARDRAIL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_pii_entity_action_none_fails(self):
        """The proven false PASS: a policy present, detecting, and taking no action."""
        result = _run_check(
            _api_call({"piiEntities": [{"type": "EMAIL", "action": "NONE"}]})
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Bedrock Guardrail test detects but does not block or mask PII entity EMAIL on the output path, so matched sensitive information still reaches the caller."
        )
        assert result[0].resource_arn == GUARDRAIL_ARN

    @mock_aws
    def test_one_entity_of_several_set_to_none_fails(self):
        """One NONE entry among enforcing ones must FAIL and name only the NONE entry.

        The claim is universal, so a single unenforced entry decides it; naming the compliant
        EMAIL entry alongside it would misdirect remediation at the entry that is already correct.
        """
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {"type": "EMAIL", "action": "ANONYMIZE"},
                        {"type": "AWS_SECRET_KEY", "action": "NONE"},
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PII entity AWS_SECRET_KEY" in result[0].status_extended
        assert "PII entity EMAIL" not in result[0].status_extended

    @mock_aws
    def test_regex_action_none_fails(self):
        """A regex set to NONE must FAIL even when every PII entity blocks.

        regexes and piiEntities leak identically, so the check must read both arms of the policy;
        an implementation that walked only piiEntities would PASS this guardrail.
        """
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [{"type": "EMAIL", "action": "BLOCK"}],
                    "regexes": [
                        {
                            "name": "internal-token",
                            "pattern": "tok-[0-9]+",
                            "action": "NONE",
                        }
                    ],
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "regex internal-token" in result[0].status_extended

    @mock_aws
    def test_regex_block_passes(self):
        """A lone regex set to BLOCK must PASS, with the singular noun in the message.

        A policy carrying only regexes and no piiEntities is a valid configuration, so it must
        reach PASS rather than falling through the entity loop into a default verdict.
        """
        result = _run_check(
            _api_call(
                {
                    "regexes": [
                        {
                            "name": "internal-token",
                            "pattern": "tok-[0-9]+",
                            "action": "BLOCK",
                        }
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        # Singular: "all 1 ... entries" was a noun/count disagreement corrected in #12459 --
        # match the noun to the count.
        assert (
            "its 1 configured sensitive information entry" in result[0].status_extended
        )

    @mock_aws
    def test_output_action_none_overrides_enforcing_action(self):
        """outputAction is the output-path setting and wins over `action` when reported."""
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {
                            "type": "EMAIL",
                            "action": "ANONYMIZE",
                            "outputAction": "NONE",
                        }
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PII entity EMAIL" in result[0].status_extended

    @mock_aws
    def test_output_action_enforcing_with_action_none_passes(self):
        """action NONE with outputAction BLOCK must PASS: the output path is what this check judges.

        The converse of test_output_action_none_overrides_enforcing_action. Reading `action` first
        would FAIL a guardrail that does block on output, so this pins the precedence in the
        direction where getting it wrong produces a false positive.
        """
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {"type": "EMAIL", "action": "NONE", "outputAction": "BLOCK"}
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_output_evaluation_disabled_fails(self):
        """An enforcing action never runs when output evaluation is switched off."""
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {
                            "type": "EMAIL",
                            "action": "BLOCK",
                            "outputEnabled": False,
                        }
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PII entity EMAIL" in result[0].status_extended

    @mock_aws
    def test_output_enabled_absent_is_not_treated_as_disabled(self):
        """GetGuardrail omits outputEnabled unless it was set; absent must not read as False."""
        result = _run_check(
            _api_call({"piiEntities": [{"type": "EMAIL", "action": "BLOCK"}]})
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_absent_action_is_manual_not_pass(self):
        """An action the API did not report is unknown, not compliant and not a falsy default."""
        result = _run_check(_api_call({"piiEntities": [{"type": "EMAIL"}]}))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Bedrock Guardrail test did not report an action for PII entity EMAIL; verify manually that matches are blocked or masked on the output path."
        )

    @mock_aws
    def test_proven_leak_outranks_an_unreported_action(self):
        """A guardrail with both an unknown and a NONE entry must FAIL, and still name the unknown.

        The original intent here was that such a guardrail "must not silently PASS or FAIL-only" --
        the worry being that a bare FAIL would drop the unreported entry. Reporting MANUAL solved
        that but created a worse problem: one entry whose action the API omitted hid an entry proven
        to take no action, so a provable leak read as merely unknown. This check makes a universal
        claim (every entry must block or mask), so one entry known to take no action settles it,
        which is the rule the maintainer applied on #12459 -- "definite draft sharing outranks an
        incomplete alias inventory". The unknown is still disclosed, in the FAIL message.
        """
        result = _run_check(
            _api_call(
                {
                    "piiEntities": [
                        {"type": "EMAIL"},
                        {"type": "NAME", "action": "NONE"},
                    ]
                }
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PII entity NAME" in result[0].status_extended
        assert "PII entity EMAIL" in result[0].status_extended
        assert "was not reported" in result[0].status_extended

    @mock_aws
    def test_fail_message_is_stable_under_entry_reordering(self):
        """The FAIL message must be byte identical when GetGuardrail returns the entries reversed.

        GetGuardrail documents no ordering for piiEntities or regexes, so the same unchanged
        guardrail can be returned entry-reversed on the next scan. Both rendered lists are built by
        append and joined, so without a sort one unchanged guardrail produces two different
        status_extended strings, which downstream reads as a finding that changed.
        """
        entries = [
            {"type": "EMAIL", "action": "NONE"},
            {"type": "ADDRESS", "action": "NONE"},
            {"type": "NAME"},
            {"type": "AGE"},
        ]
        forward = _run_check(_api_call({"piiEntities": entries}))
        reversed_ = _run_check(_api_call({"piiEntities": list(reversed(entries))}))

        assert len(forward) == 1 and len(reversed_) == 1
        # Both lists are asserted to render in sorted order before the two runs are compared: two
        # runs that both rendered no entry names at all would be byte identical and prove nothing.
        assert forward[0].status == "FAIL" and reversed_[0].status == "FAIL"
        message = forward[0].status_extended
        assert "PII entity ADDRESS, PII entity EMAIL" in message, message
        assert "PII entity AGE, PII entity NAME" in message, message
        assert message == reversed_[0].status_extended

    @mock_aws
    def test_manual_message_is_stable_under_entry_reordering(self):
        """The MANUAL message must be byte identical when the unreported entries arrive reversed.

        The MANUAL branch renders the unreported list a second time, so it needs its own sort; a
        sort placed only on the FAIL path leaves this message unstable.
        """
        entries = [{"type": "NAME"}, {"type": "AGE"}]
        forward = _run_check(_api_call({"piiEntities": entries}))
        reversed_ = _run_check(_api_call({"piiEntities": list(reversed(entries))}))

        assert len(forward) == 1 and len(reversed_) == 1
        assert forward[0].status == "MANUAL" and reversed_[0].status == "MANUAL"
        message = forward[0].status_extended
        assert "PII entity AGE, PII entity NAME" in message, message
        assert message == reversed_[0].status_extended

    @mock_aws
    def test_every_guardrail_is_reported(self):
        """One report per in-scope guardrail: a loop that stops early must not read as clean."""
        result = _run_check(_api_call_two_guardrails)

        assert len(result) == 2
        by_id = {report.resource_id: report for report in result}
        assert by_id["test-id"].status == "PASS"
        assert by_id["second-id"].status == "FAIL"
        assert "PII entity EMAIL" in by_id["second-id"].status_extended

    @mock_aws
    def test_unreadable_guardrail_detail_is_manual_not_pass(self):
        """GetGuardrail denied must not be reported as a compliant guardrail."""
        error = botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "not authorized to perform: bedrock:GetGuardrail",
                }
            },
            "GetGuardrail",
        )
        result = _run_check(_api_call(get_guardrail_error=error))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Bedrock Guardrail test configuration could not be retrieved (AccessDeniedException); verify manually that its sensitive information filters block or mask matches on the output path."
        )
        assert result[0].resource_arn == GUARDRAIL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
