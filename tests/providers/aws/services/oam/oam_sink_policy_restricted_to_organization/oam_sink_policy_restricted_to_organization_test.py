from unittest import mock

import pytest

from prowler.providers.aws.services.oam.oam_service import Sink, SinkPolicyState
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

SINK_NAME = "central-monitoring"
SINK_ID = "abcd1234-a123-456a-a12b-a123b456c789"
SINK_ARN = f"arn:aws:oam:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:sink/{SINK_ID}"

ORGANIZATION_ID = "o-a1b2c3d4e5"


def _policy(statement):
    """Wraps a statement, or a list of them, in a sink resource policy document."""
    return {"Version": "2012-10-17", "Statement": statement}


def _link_statement(**overrides):
    """Builds an Allow statement granting oam:CreateLink to every principal.

    Args:
        overrides: Statement members to replace, such as Condition or Principal.
    """
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": ["oam:CreateLink", "oam:UpdateLink"],
        "Resource": "*",
    }
    statement.update(overrides)
    return statement


def _run_check(sinks):
    """Runs the check against the given sinks, with the OAM client mocked out.

    Args:
        sinks: Mapping of sink ARN to Sink, as oam_client.sinks would hold.
    """
    oam_client = mock.MagicMock()
    oam_client.sinks = sinks
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ),
        mock.patch(
            "prowler.providers.aws.services.oam.oam_sink_policy_restricted_to_organization.oam_sink_policy_restricted_to_organization.oam_client",
            new=oam_client,
        ),
    ):
        from prowler.providers.aws.services.oam.oam_sink_policy_restricted_to_organization.oam_sink_policy_restricted_to_organization import (
            oam_sink_policy_restricted_to_organization,
        )

        return oam_sink_policy_restricted_to_organization().execute()


def _check_module():
    """Imports the check module, which builds its client singleton at import time."""
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
    ):
        from prowler.providers.aws.services.oam.oam_sink_policy_restricted_to_organization import (
            oam_sink_policy_restricted_to_organization as check_module,
        )

        return check_module


def _one_sink(policy, policy_state):
    """Builds the single-sink mapping the check iterates over.

    Args:
        policy: The decoded resource policy, or None.
        policy_state: The SinkPolicyState the collector determined.
    """
    return {
        SINK_ARN: Sink(
            arn=SINK_ARN,
            id=SINK_ID,
            name=SINK_NAME,
            region=AWS_REGION_EU_WEST_1,
            policy=policy,
            policy_state=policy_state,
            tags=[{"environment": "production"}],
        )
    }


class Test_oam_sink_policy_restricted_to_organization:
    def test_no_sinks(self):
        """An account with no sinks produces no findings."""
        assert _run_check({}) == []

    def test_sink_policy_unreadable(self):
        """A sink whose policy could not be determined is MANUAL, not a proven outcome."""
        result = _run_check(_one_sink(None, SinkPolicyState.UNKNOWN))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Observability Access Manager sink {SINK_NAME} resource policy could not be "
            "determined, so the accounts able to link to it are unknown; review it manually."
        )
        assert result[0].resource_id == SINK_ID
        assert result[0].resource_arn == SINK_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1
        assert result[0].resource_tags == [{"environment": "production"}]

    def test_sink_without_policy(self):
        """A sink with no resource policy PASSes because no account can link to it."""
        result = _run_check(_one_sink(None, SinkPolicyState.ABSENT))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Observability Access Manager sink {SINK_NAME} does not have a resource "
            "policy, so no account can link to it."
        )
        assert result[0].resource_arn == SINK_ARN

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringEquals": {"aws:PrincipalOrgID": ORGANIZATION_ID}
                            }
                        )
                    ]
                ),
                id="principal_org_id",
            ),
            # Counterweights to the partially wildcarded IDs in the unscoped cases below.
            # Demanding a COMPLETE organization ID must not reject a value that names one:
            # the ID is finished here, whether the value ends there or carries the path
            # delimiter and a wildcard below it.
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringLike": {"aws:PrincipalOrgID": ORGANIZATION_ID}
                            }
                        )
                    ]
                ),
                id="complete_organization_id_under_string_like",
            ),
            # AWS documents the ID as "o-" followed by 10 to 32 lowercase letters or
            # digits, so the upper bound has to admit one of the full 32.
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringEquals": {
                                    "aws:PrincipalOrgID": "o-" + "a1b2c3d4e5" * 3 + "ab"
                                }
                            }
                        )
                    ]
                ),
                id="maximum_length_organization_id",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                }
                            }
                        )
                    ]
                ),
                id="whole_tree_under_a_complete_organization_id",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": [
                                        f"{ORGANIZATION_ID}/r-ab12/ou-ab12-11111111/"
                                        "ou-ab12-22222222/*"
                                    ]
                                }
                            }
                        )
                    ]
                ),
                id="deeper_path_under_a_complete_organization_id",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": [
                                        f"{ORGANIZATION_ID}/r-ab12/ou-ab12-11111111/*"
                                    ]
                                }
                            }
                        )
                    ]
                ),
                id="principal_org_paths_wildcard_below_org",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringEquals": {
                                    "aws:PrincipalOrgPaths": [
                                        f"{ORGANIZATION_ID}/r-ab12/ou-ab12-11111111/"
                                    ]
                                }
                            }
                        )
                    ]
                ),
                id="principal_org_paths_exact",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                },
                                # Without this, ForAllValues would also admit a principal
                                # carrying no aws:PrincipalOrgPaths at all.
                                "Null": {"aws:PrincipalOrgPaths": "false"},
                            }
                        )
                    ]
                ),
                id="for_all_values_with_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringEquals": {
                                    "aws:PrincipalOrgID": ORGANIZATION_ID
                                },
                                "Null": {"aws:PrincipalOrgID": "false"},
                            }
                        )
                    ]
                ),
                id="for_all_values_org_id_with_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Principal={"AWS": ["111122223333", "444455556666"]}
                        )
                    ]
                ),
                id="enumerated_accounts",
            ),
            pytest.param(
                _policy([_link_statement(Effect="Deny")]),
                id="deny_statement_only",
            ),
            pytest.param(
                _policy(
                    _link_statement(
                        Condition={
                            "StringEquals": {"aws:PrincipalOrgID": ORGANIZATION_ID}
                        }
                    )
                ),
                id="single_statement_object",
            ),
            # An open principal on a read-only sink action grants visibility, not a link, so
            # it is not this finding no matter how broad the principal is.
            pytest.param(
                _policy([_link_statement(Action=["oam:GetSinkPolicy"])]),
                id="read_only_action_only",
            ),
            pytest.param(
                _policy([_link_statement(Action="oam:GetSinkPolicy")]),
                id="read_only_action_as_bare_string",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Action=[
                                "oam:GetSink",
                                "oam:ListAttachedLinks",
                                "oam:ListTagsForResource",
                            ]
                        )
                    ]
                ),
                id="every_read_only_sink_action",
            ),
            # IAM matches action names without regard to case.
            pytest.param(
                _policy([_link_statement(Action=["OAM:GETSINKPOLICY", "oam:getsink"])]),
                id="read_only_action_in_another_case",
            ),
        ],
    )
    def test_sink_policy_scoped(self, policy):
        """A policy that genuinely constrains who may link PASSes.

        Args:
            policy: A sink resource policy that restricts linking.
        """
        result = _run_check(_one_sink(policy, SinkPolicyState.AVAILABLE))

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Observability Access Manager sink {SINK_NAME} has a resource policy "
            "restricting which accounts can link to it."
        )
        assert result[0].resource_arn == SINK_ARN

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param(_policy([_link_statement()]), id="wildcard_principal_string"),
            pytest.param(
                _policy([_link_statement(Principal={"AWS": "*"})]),
                id="wildcard_principal_aws",
            ),
            pytest.param(
                _policy([_link_statement(Principal={"AWS": ["*", "111122223333"]})]),
                id="wildcard_among_enumerated_accounts",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringNotEquals": {
                                    "aws:PrincipalOrgID": ORGANIZATION_ID
                                }
                            }
                        )
                    ]
                ),
                id="inverted_organization_condition",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringEqualsIfExists": {
                                    "aws:PrincipalOrgID": ORGANIZATION_ID
                                }
                            }
                        )
                    ]
                ),
                id="if_exists_organization_condition",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={"StringLike": {"aws:PrincipalOrgID": "*"}}
                        )
                    ]
                ),
                id="wildcard_organization_value",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={"StringLike": {"aws:PrincipalOrgID": "o-*"}}
                        )
                    ]
                ),
                id="organization_id_pattern_matches_every_organization",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": ["o-*/*"]
                                }
                            }
                        )
                    ]
                ),
                id="organization_path_pattern_matches_every_organization",
            ),
            # A wildcard reaching into the organization ID leaves it unfinished, so the
            # condition admits every organization whose ID begins with the literal text
            # rather than the single one the author appears to have named.
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={"StringLike": {"aws:PrincipalOrgID": "o-a*"}}
                        )
                    ]
                ),
                id="organization_id_wildcarded_after_one_character",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={"StringLike": {"aws:PrincipalOrgID": "o-a1b2c*"}}
                        )
                    ]
                ),
                id="organization_id_wildcarded_part_way_through",
            ),
            # IDs run to 32 characters, so a wildcard sitting where the next character of
            # the ID could go still matches every longer ID beginning with these ten. Only
            # the path delimiter, or the end of the value, finishes an ID.
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringLike": {
                                    "aws:PrincipalOrgID": f"{ORGANIZATION_ID}*"
                                }
                            }
                        )
                    ]
                ),
                id="wildcard_directly_after_a_complete_organization_id",
            ),
            # StringLike honours ? as exactly one character, so the ID's last character is
            # unknown. Short of the documented minimum length here, and of full length in
            # the case below, the value names more than one organization either way.
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringLike": {
                                    "aws:PrincipalOrgID": f"{ORGANIZATION_ID[:-1]}?"
                                }
                            }
                        )
                    ]
                ),
                id="organization_id_truncated_by_a_single_character_wildcard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "StringLike": {
                                    "aws:PrincipalOrgID": f"{ORGANIZATION_ID}?"
                                }
                            }
                        )
                    ]
                ),
                id="single_character_wildcard_after_a_complete_organization_id",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": ["o-a1b2c*/*"]
                                }
                            }
                        )
                    ]
                ),
                id="organization_path_under_a_wildcarded_organization_id",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                }
                            }
                        )
                    ]
                ),
                id="for_all_values_without_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringEquals": {
                                    "aws:PrincipalOrgID": ORGANIZATION_ID
                                }
                            }
                        )
                    ]
                ),
                id="for_all_values_org_id_without_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                },
                                # Null: true requires the key to be ABSENT, so it widens
                                # the grant instead of narrowing it.
                                "Null": {"aws:PrincipalOrgPaths": "true"},
                            }
                        )
                    ]
                ),
                id="for_all_values_with_inverted_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                },
                                # The guard names the other organization key, so
                                # aws:PrincipalOrgPaths may still be absent.
                                "Null": {"aws:PrincipalOrgID": "false"},
                            }
                        )
                    ]
                ),
                id="for_all_values_with_null_guard_on_another_key",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringLike": {
                                    "aws:PrincipalOrgPaths": [f"{ORGANIZATION_ID}/*"]
                                },
                                "Null": "false",
                            }
                        )
                    ]
                ),
                id="for_all_values_with_malformed_null_guard",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAnyValue:StringLike": {
                                    "aws:PrincipalOrgPaths": [
                                        "*",
                                        f"{ORGANIZATION_ID}/*",
                                    ]
                                }
                            }
                        )
                    ]
                ),
                id="wildcard_among_organization_paths",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Condition={
                                "ForAllValues:StringEquals": {
                                    "oam:ResourceTypes": ["AWS::Logs::LogGroup"]
                                }
                            }
                        )
                    ]
                ),
                id="unrelated_condition_key",
            ),
            pytest.param(
                _policy(
                    [
                        {
                            "Effect": "Allow",
                            "NotPrincipal": {"AWS": ["111122223333"]},
                            "Action": ["oam:CreateLink"],
                            "Resource": "*",
                        }
                    ]
                ),
                id="not_principal",
            ),
            pytest.param(
                _policy(
                    [
                        _link_statement(
                            Effect="Deny",
                            Condition={
                                "StringEquals": {"aws:PrincipalOrgID": ORGANIZATION_ID}
                            },
                        ),
                        _link_statement(),
                    ]
                ),
                id="unscoped_allow_after_scoped_deny",
            ),
            pytest.param(
                _policy(_link_statement()),
                id="single_statement_object",
            ),
            # Counterweights to the read-only cases above. Narrowing by action must not let
            # any of these through, because each one can still reach a link.
            pytest.param(
                _policy([_link_statement(Action=["oam:CreateLink"])]),
                id="create_link_alone",
            ),
            pytest.param(
                _policy([_link_statement(Action=["oam:UpdateLink"])]),
                id="update_link_alone",
            ),
            # PutSinkPolicy replaces the policy, so it grants the holder oam:CreateLink.
            pytest.param(
                _policy([_link_statement(Action=["oam:PutSinkPolicy"])]),
                id="put_sink_policy_can_grant_linking",
            ),
            pytest.param(
                _policy([_link_statement(Action="oam:*")]),
                id="wildcard_over_the_oam_namespace",
            ),
            pytest.param(
                _policy([_link_statement(Action="*")]),
                id="wildcard_over_every_action",
            ),
            pytest.param(
                _policy([_link_statement(Action="oam:Create*")]),
                id="wildcard_over_the_create_actions",
            ),
            pytest.param(
                _policy([_link_statement(Action="oam:Get?ink")]),
                id="single_character_wildcard",
            ),
            # IAM has no [seq] character class, so this matches no action at all. Reading it
            # as one, as fnmatch would, would rule the statement out on a false match.
            pytest.param(
                _policy([_link_statement(Action=["oam:Get[sS]ink"])]),
                id="character_class_is_not_an_iam_wildcard",
            ),
            pytest.param(
                _policy([_link_statement(Action=["oam:GetSink", "oam:CreateLink"])]),
                id="read_only_action_alongside_a_link_action",
            ),
            pytest.param(
                _policy(
                    [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            # Excluding an unrelated service leaves all of OAM permitted.
                            "NotAction": ["s3:*"],
                            "Resource": "*",
                        }
                    ]
                ),
                id="not_action_excluding_another_service",
            ),
            pytest.param(
                _policy(
                    [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Resource": "*",
                        }
                    ]
                ),
                id="no_action_member_at_all",
            ),
            pytest.param(
                _policy([_link_statement(Action=[])]),
                id="empty_action_list",
            ),
        ],
    )
    def test_sink_policy_unscoped(self, policy):
        """A policy that leaves an account outside the organization able to link FAILs.

        Args:
            policy: A sink resource policy that does not restrict linking.
        """
        result = _run_check(_one_sink(policy, SinkPolicyState.AVAILABLE))

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Observability Access Manager sink {SINK_NAME} has a resource policy "
            "allowing any AWS account to link to it without restricting them to an "
            "organization."
        )
        assert result[0].resource_arn == SINK_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_sinks_reported_independently(self):
        """Each sink gets its own status and region rather than a shared verdict."""
        second_arn = (
            f"arn:aws:oam:us-east-1:{AWS_ACCOUNT_NUMBER}:sink/11111111-2222-3333"
        )
        sinks = _one_sink(_policy([_link_statement()]), SinkPolicyState.AVAILABLE)
        sinks[second_arn] = Sink(
            arn=second_arn,
            id="11111111-2222-3333",
            name="secondary-monitoring",
            region="us-east-1",
            policy=None,
            policy_state=SinkPolicyState.ABSENT,
        )

        result = _run_check(sinks)

        statuses = {report.resource_arn: report.status for report in result}
        assert statuses == {SINK_ARN: "FAIL", second_arn: "PASS"}
        regions = {report.resource_arn: report.region for report in result}
        assert regions == {SINK_ARN: AWS_REGION_EU_WEST_1, second_arn: "us-east-1"}

    def test_no_inert_action_contains_an_iam_wildcard(self):
        """Every INERT_SINK_ACTIONS member must be a wildcard-free literal.

        The exclusion path is exact set membership, and that is only safe because no
        member can match more than itself. Adding an entry like "oam:get*" would make the
        allowlist pattern-like, which is the design this check deliberately avoids: IAM
        honours only * and ?, so a pattern in the allowlist would exclude statements it
        does not name.
        """
        check_module = _check_module()

        # Without this the loop below would pass on an empty set, which is the one way the
        # allowlist could change and take the invariant with it unnoticed.
        assert check_module.INERT_SINK_ACTIONS
        for action in check_module.INERT_SINK_ACTIONS:
            assert not check_module.WILDCARD.search(action), action
