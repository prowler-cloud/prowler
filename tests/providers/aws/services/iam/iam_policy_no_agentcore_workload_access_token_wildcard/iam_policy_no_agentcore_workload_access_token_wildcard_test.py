from unittest import mock

import pytest

from prowler.providers.aws.services.iam.iam_service import Policy
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_ID = "123456789012"
DIRECTORY_ARN = f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:workload-identity-directory/default"
WORKLOAD_ARN = f"{DIRECTORY_ARN}/workload-identity/my-agent-abc123"
TOKEN_VAULT_ARN = f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:token-vault/default/oauth2credentialprovider/my-provider"

CHECK_MODULE = "prowler.providers.aws.services.iam.iam_policy_no_agentcore_workload_access_token_wildcard.iam_policy_no_agentcore_workload_access_token_wildcard"


def _policy(
    statements,
    name: str = "policy",
    policy_type: str = "Custom",
    attached: bool = True,
    document_present: bool = True,
):
    """Build a customer-managed Policy, with the document present unless told otherwise.

    `document_present=False` reproduces a policy whose GetPolicyVersion call failed, which the
    collector leaves as a None document rather than an empty one.
    """
    document = None
    if document_present:
        document = {"Version": "2012-10-17", "Statement": statements}
    return Policy(
        name=name,
        arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/{name}",
        entity="ANPAEXAMPLEPOLICYID",
        version_id="v1",
        type=policy_type,
        attached=attached,
        document=document,
    )


def _run(policies: list, scan_unused_services: bool = True):
    """Execute the check against the given policies and return its reports.

    The policies are model objects, so the reports exercise the check's own statement parsing
    without any IAM API call.
    """
    iam_client = mock.MagicMock()
    iam_client.policies = {policy.arn: policy for policy in policies}
    iam_client.region = AWS_REGION_US_EAST_1
    iam_client.provider.scan_unused_services = scan_unused_services

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.aws.services.iam.iam_policy_no_agentcore_workload_access_token_wildcard.iam_policy_no_agentcore_workload_access_token_wildcard import (
            iam_policy_no_agentcore_workload_access_token_wildcard,
        )

        return iam_policy_no_agentcore_workload_access_token_wildcard().execute()


class Test_iam_policy_no_agentcore_workload_access_token_wildcard:
    def test_no_policies(self):
        """An account with no customer-managed policies produces no reports at all."""
        assert len(_run([])) == 0

    def test_aws_managed_policy_not_evaluated(self):
        """An AWS-managed policy is out of the population even when it grants the tokens.

        The fixture is BedrockAgentCoreFullAccess-shaped, so it would FAIL on merit; a zero here
        therefore measures the type filter and not an absence of violations.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "arn:aws:bedrock-agentcore:*:*:*",
                }
            ],
            policy_type="AWS",
        )
        assert len(_run([policy])) == 0

    def test_inline_policy_not_evaluated(self):
        """An inline policy is out of the population: a separate check owns that surface."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ],
            policy_type="Inline",
        )
        assert len(_run([policy])) == 0

    def test_unattached_policy_skipped_without_scan_unused_services(self):
        """An unattached policy is judged only when scan_unused_services is on.

        Both directions are asserted from one fixture, so the flag is shown to be what decides it
        rather than something about the policy.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ],
            attached=False,
        )
        assert len(_run([policy], scan_unused_services=False)) == 0
        assert _run([policy], scan_unused_services=True)[0].status == "FAIL"

    def test_unreadable_document_is_manual(self):
        """A policy whose document was never retrieved must be MANUAL, never PASS.

        An unread document is exactly where a token grant would hide, so reporting compliance from
        it would assert something that was never established.
        """
        policy = _policy([], name="unreadable", document_present=False)
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Custom Policy unreadable could not be evaluated because its policy document was not retrieved."
        )

    def test_policy_without_agentcore_actions_passes(self):
        """A policy naming no AgentCore action at all must PASS, with its identity fields set.

        Also pins resource id, ARN and region, which the rest of the file takes for granted.
        """
        policy = _policy(
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            name="s3_reader",
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Custom Policy s3_reader does not allow AgentCore workload access token retrieval outside a workload identity ARN."
        )
        assert result[0].resource_id == "s3_reader"
        assert (
            result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/s3_reader"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_scoped_to_workload_identity_arns_passes(self):
        """Both the directory ARN and a workload-identity child ARN are an accepted scope.

        This is the shape the AgentCore console issues for a gateway's own identity, so a FAIL here
        would report the product's own default as a misconfiguration.
        """
        policy = _policy(
            [
                {
                    "Sid": "GetWorkloadAccessToken",
                    "Effect": "Allow",
                    "Action": ["bedrock-agentcore:GetWorkloadAccessToken"],
                    "Resource": [DIRECTORY_ARN, WORKLOAD_ARN],
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_wildcard_within_directory_namespace_passes(self):
        """A wildcard confined to the workload-identity namespace is still a scope, so PASS."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "Resource": f"{DIRECTORY_ARN}/workload-identity/my-gateway-*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_directory_arn_without_child_passes(self):
        """The bare workload-identity-directory ARN, naming no child, is an accepted scope."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": DIRECTORY_ARN,
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_other_agentcore_resource_type_passes(self):
        """A token action pointed at a token-vault ARN reaches no workload identity, so PASS.

        The token operations accept no token-vault resource, so the grant is inert rather than
        broad, and reporting it would be a false positive.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetResourceOauth2Token",
                    ],
                    "Resource": [TOKEN_VAULT_ARN],
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_another_service_resource_passes(self):
        """A token action in a statement whose resources belong to another service must PASS.

        However wide the S3 wildcard is, it names no workload identity, so the token action it sits
        beside grants nothing this check is about.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "s3:GetObject",
                    ],
                    "Resource": "arn:aws:s3:::*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_wildcard_across_the_whole_directory_namespace_passes(self):
        """A wildcard spanning every workload identity in the directory is still in-namespace, so PASS.

        The ARN type is the granularity this check asserts; narrowing further is a different claim.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": f"{DIRECTORY_ARN}/workload-identity/*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_one_broad_resource_among_scoped_ones_fails(self):
        """A single "*" beside correctly scoped ARNs must FAIL: IAM evaluates each Resource on its own."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": [WORKLOAD_ARN, "*"],
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_resource_fails(self):
        """A token action on Resource "*" must FAIL, and the report must name the operation.

        The full sentence is asserted, so a reworded finding cannot pass silently.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": ["bedrock-agentcore:GetWorkloadAccessToken"],
                    "Resource": "*",
                }
            ],
            name="obo_permissions",
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Custom Policy obo_permissions allows bedrock-agentcore:GetWorkloadAccessToken "
            "on resources outside a workload identity ARN, so its resources do not confine "
            "token retrieval to the workload's own identity; conditions on the statement are "
            "not evaluated."
        )

    def test_condition_narrowed_statement_still_fails_without_claiming_capability(self):
        """A grant narrowed only by aws:ResourceTag still FAILs, and the text says why it might not.

        `_is_workload_identity_scoped` reads Resource and NotResource and never Condition, the
        mirror of the Deny-side rule that a conditional Deny is not credited with removing a
        permission. FAILing is deliberate conservatism -- a tag condition is not the ARN-level
        scope this check asserts -- but the finding must not then assert that the holder CAN mint
        tokens for other identities, which this condition may already prevent. So the sentence
        claims only that the resources do not confine it, and discloses that conditions are unread.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"
                        }
                    },
                }
            ],
            name="tag_scoped",
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "conditions on the statement are not evaluated" in result[0].status_extended
        )
        assert "can mint" not in result[0].status_extended

    def test_service_wildcard_action_fails_on_all_three_operations(self):
        """bedrock-agentcore:* covers all three token operations, and all three must be named.

        The order is asserted too, since the finding renders them sorted.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                }
            ],
            name="agentcore_all",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert (
            "bedrock-agentcore:GetWorkloadAccessToken, "
            "bedrock-agentcore:GetWorkloadAccessTokenForJWT, "
            "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
        ) in result[0].status_extended

    def test_operation_prefix_wildcard_fails(self):
        """A prefix wildcard such as GetWorkload* reaches the token operations, so it must FAIL."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkload*",
                    "Resource": "*",
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_all_wildcard_agentcore_arn_fails(self):
        """An all-wildcard AgentCore ARN is not a workload-identity scope, so it must FAIL.

        Only the granted operation is named: the finding must not list operations the Action never
        covered, which is what the negative assertion pins.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "arn:aws:bedrock-agentcore:*:*:*",
                }
            ],
            name="wildcard_arn",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert (
            "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
            in result[0].status_extended
        )
        assert "GetWorkloadAccessTokenForJWT" not in result[0].status_extended

    def test_partial_wildcard_service_field_fails(self):
        """A PARTIAL wildcard in the ARN's service field still names AgentCore, so it must FAIL.

        `bedrock-*` matches bedrock-agentcore, so with an all-wildcard resource field the grant
        reaches every workload identity. An exact-membership test on that field recognised `*` but
        not `bedrock-*`, and reported PASS -- the direction that does not self-correct, since a
        false PASS is filed as clean and nobody looks again. The service field is now matched as an
        IAM pattern, the same way the resource field already was.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": f"arn:aws:bedrock-*:us-east-1:{AWS_ACCOUNT_ID}:*",
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_unrelated_service_in_the_arn_still_passes(self):
        """An ARN for an unrelated service must still be out of reach, so PASS.

        The guard against the fix above over-reaching: `s3` is matched as a pattern too, and must
        not match bedrock-agentcore. Without this, widening the service-field test could quietly
        pull every S3 grant into the check.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": f"arn:aws:s3:us-east-1:{AWS_ACCOUNT_ID}:*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "resource",
        [
            f"*:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:*",
            "*:*:*:*:*:*",
            "arn:aws:bedrock-agentcore:*",
            "arn:aws:*",
            "arn:*",
        ],
    )
    def test_a_star_spanning_arn_fields_still_reaches_every_workload_identity(
        self, resource
    ):
        """A star anywhere in the ARN that can span fields must FAIL.

        Every one of these PASSed. Two separate causes, both of which made a BROADER pattern
        score better than the correctly spelled six-field equivalent that already FAILed:
        comparing the first field to the literal "arn" rejected the two that wildcard it, and a
        fewer-than-six-fields test rejected the three that are short because a star absorbs the
        rest. IAM wildcards match the colon, so none of these is narrower than `arn:aws:...:*`.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": resource,
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:bedrock-agentcore:us-west-2:*",
            "arn:aws:bedrock-agentcore:eu-central-1:*",
            "arn:aws-cn:bedrock-agentcore:*",
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}*",
            "arn:aws:bedrock-agentcore:us-east-1:178113193057*",
        ],
    )
    def test_a_truncated_arn_reaches_workload_identities_in_any_region_or_account(
        self, resource
    ):
        """A short starred ARN must FAIL whatever region, account or partition it names.

        The previous fix matched short ARNs against ONE concrete probe pinned to us-east-1 and
        123456789012, which made those two values load-bearing: `us-west-2:*` PASSed while the
        byte-identical `us-east-1:*` FAILed, so the check cleared the common spelling and reported
        only the one nobody writes. AgentCore is generally available outside us-east-1 and that
        account is a documentation placeholder.

        An account PREFIX is the case that shows no probe corpus could have fixed it -- there is
        nothing to enumerate -- so the short form is now decided structurally: a star in the last
        spelled-out field spans every field after it, because IAM wildcards match the colon.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": resource,
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource",
        [
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:workload-identity-*",
            "arn:aws:bedrock-agentcore:*:*:workload-identity-directory*",
        ],
    )
    def test_a_resource_confined_to_the_workload_identity_namespace_passes(
        self, resource
    ):
        """A resource confined to the workload-identity namespace PASSes however it is spelled.

        These two were ordered backwards: `workload-identity-*` FAILed while the strictly BROADER
        `workload-identity-directory*` -- whose reach is a superset of it, across every account and
        partition -- PASSed. The cause was a startswith test on the literal namespace prefix, which
        asks whether the field BEGINS with it rather than whether it can reach outside it. Confinement
        is now decided by whether the field can name a resource of another AgentCore type.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": resource,
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "resource_field",
        ["*prod-*", "*/customer-support-agent*", "*chatbot", "*-agent*"],
    )
    def test_a_name_keyed_wildcard_escapes_the_namespace_and_fails(
        self, resource_field
    ):
        """A resource field wildcarded on a NAME reaches other AgentCore types, so it must FAIL.

        `*prod-*` matches workload-identity-directory/default/workload-identity/prod-chatbot AND
        .../prod-agent -- two distinct identities -- and also runtime/prod-chatbot,
        gateway/prod-chatbot-gw, memory/prod-chatbot-mem, a token vault and a custom browser. It
        PASSed, because confinement was decided by matching four concrete probe resources whose
        example NAMES were load-bearing: token-vault/default, gateway/my-gateway, runtime/my-runtime
        and one workload identity called another-workload. A field keyed on any other name matched
        none of them, so the check read it as confined to the namespace and cleared it.

        The decisive pair is `*` versus `*prod-*`: the first FAILed and the second PASSed, and nothing
        stated in the check separated them. Both reach a workload identity and both escape the
        namespace, so both must FAIL. These names are not invented -- the AgentCore devguide's own
        examples are prod-chatbot, dev-chatbot and customer-support-agent, identities it creates
        automatically named after the runtime or gateway that made them, and its own example policy
        wildcards on the name.

        Confinement is now decided against the enumerable list of AgentCore resource-path SEGMENTS
        from AWS's service reference, because types can be enumerated and names cannot.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    ],
                    "Resource": (
                        f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:{resource_field}"
                    ),
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource_field",
        [
            "?orkload-identity-directory/*",
            "?orkload-identity-directory/default/workload-identity/*",
            "??orkload-identity-directory/*",
            "?untime/*",
            "?",
        ],
    )
    def test_a_question_mark_consumes_one_character_not_a_span(self, resource_field):
        """`?` matches EXACTLY ONE character, so a field leading with it is not a field leading with `*`.

        These PASS because none of them can name a resource of another AgentCore type: `?orkload-...`
        matches only strings whose first character is arbitrary and whose remainder is the literal
        namespace path, and no other resource type ends up under that shape. `?untime/*` matches nothing
        at all, since no AgentCore segment is `?untime`.

        This is a regression I shipped and these fixtures are what would have caught it. The reach test
        cut the field's head at the first `*` OR `?`, treating them alike, so a leading `?` emptied the
        head; an empty head is compatible with every segment, so the field was read as reaching all 22
        of them and then as escaping the namespace. An exact oracle over 1345 fields found 265 false
        FAILs, every one `?`-leading, and replacing the first character of the nine pinned-PASS fields
        with `?` flipped nine of nine.

        Bare `?` IS here, and getting it here took two corrections. It was first reported as a defect,
        then dropped because `accessanalyzer validate-policy` returns ERROR INVALID_ARN_RESOURCE for it,
        then reinstated because `create-policy` ACCEPTS and stores it. That is the third time in this
        campaign that validate-policy has contradicted create-policy, every time in the direction that
        would have discarded a real input, so create-policy is the oracle of record.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    ],
                    "Resource": (
                        f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:{resource_field}"
                    ),
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize("resource_field", ["?*", "??*"])
    def test_a_question_mark_followed_by_a_star_still_reaches_everything(
        self, resource_field
    ):
        """The FAIL direction for `?`, which no other fixture here pins.

        `?*` matches any string of length one or more, so it reaches every AgentCore resource type AND
        every workload identity: it must FAIL. The four `?` cases above are all PASS cases, so nothing
        pinned the direction where `?` MATCHING a character is what establishes reach. Stopping `?`
        from matching anything would leave the whole suite green, because every `?` fixture reaches its
        PASS verdict by a different route -- "confined" instead of "reaches nothing" -- and both routes
        end in PASS. One-directional fixtures cannot separate those.

        Both spellings are storable: create-policy accepts `?*` and `??*` as resource fields.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    ],
                    "Resource": (
                        f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:{resource_field}"
                    ),
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource_field",
        [
            "runtime/prod-*",
            "memory/prod-chatbot*",
            "gateway/*-agent",
            "tool/web-search",
        ],
    )
    def test_a_name_keyed_wildcard_on_another_type_still_passes(self, resource_field):
        """The control in the other direction: name-keyed is not by itself a finding.

        Each of these is wildcarded on a name in exactly the way the cases above are, and each reaches
        NO workload identity, so each must still PASS -- the token actions accept no runtime, memory,
        gateway or tool resource. Without these, making every name-keyed field FAIL would satisfy the
        tests above while being just as wrong in the opposite direction, and the suite could not tell
        the fix from that over-correction.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    ],
                    "Resource": (
                        f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:{resource_field}"
                    ),
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:bedrock-agentcore",
            "arn:aws:bedrock-agentcore:us-east-1",
            "arn:aws:s3:*",
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_ID}:token-vault/default",
        ],
    )
    def test_a_truncated_arn_carrying_no_star_reaches_nothing(self, resource):
        """A short ARN that reaches nothing must still PASS.

        The guard on the two fixes above. The first two carry no star, so they match no ARN at all
        and what separates them from `arn:aws:bedrock-agentcore:*` is the star, not the length.
        `arn:aws:s3:*` is short AND starred, so it guards the other direction: the fields a short
        pattern DOES spell out still have to be able to name an AgentCore ARN. The token-vault
        resource reaches a type these actions cannot name.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": resource,
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_partial_wildcard_service_in_the_action_fails(self):
        """A PARTIAL wildcard in the ACTION's service field still names AgentCore, so it must FAIL.

        `bedrock-*:GetWorkloadAccessToken` reaches the operation, and a literal comparison on that
        field read it as granting nothing at all -- so the statement was invisible to the check
        whatever its Resource said. This is the same defect as the one in the resource ARN's service
        field, one function above it, and independent of it.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-*:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_service_in_the_action_fails(self):
        """`*:GetWorkloadAccessToken` names every service, AgentCore among them, so it must FAIL."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "*:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_unrelated_service_in_the_action_still_passes(self):
        """An action for an unrelated service must stay out of reach, so PASS.

        The guard against the two fixes above over-reaching: `s3` is matched as a pattern too and
        must not match bedrock-agentcore. Without this, widening the service-field test could
        quietly pull every S3 grant into the check.
        """
        policy = _policy(
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        )
        assert _run([policy])[0].status == "PASS"

    def test_wildcard_dense_action_reaches_a_verdict(self):
        """A wildcard-dense service field must reach a verdict rather than stall the scan.

        End-to-end with an adversarial Action, on the ACTION service field specifically, because
        that surface exists only because of the pattern-matching fix: converting an O(1) string
        comparison into a match is what made it reachable. The dense field does not name
        bedrock-agentcore, so the statement grants nothing and the policy PASSes -- the point is that
        a verdict arrives at all. Timing is asserted in `Test_iam_pattern_matches` instead, where the
        matcher can be measured without several seconds of service construction around it.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": f"{'*' * 14}zzz{'*' * 14}:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ]
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_bare_action_wildcard_is_left_to_admin_checks(self):
        """A bare Action "*" is left to the administrative-privileges checks, so PASS here.

        Reporting it would duplicate check_admin_access rather than add a claim, and duplicate
        findings on one policy are what make a report harder to act on.
        """
        policy = _policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        assert _run([policy])[0].status == "PASS"

    def test_not_resource_fails(self):
        """A statement using NotResource names no resource, so it is not scoped and must FAIL."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "NotResource": TOKEN_VAULT_ARN,
                }
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_scoped_statement_does_not_rescue_a_broad_one(self):
        """A correctly scoped statement does not rescue a broad one in the same policy.

        Measured on a live gateway role. Statements are evaluated independently, so the scoped one
        cannot narrow the Resource "*" one sitting beside it.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    ],
                    "Resource": [DIRECTORY_ARN, WORKLOAD_ARN],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetPolicy",
                        "bedrock-agentcore:GetWorkloadAccessToken",
                    ],
                    "Resource": "*",
                },
            ]
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert (
            "allows bedrock-agentcore:GetWorkloadAccessToken on resources"
            in result[0].status_extended
        )

    def test_unconditional_deny_on_all_resources_clears_the_finding(self):
        """An unconditional Deny of the same action on "*" removes the permission, so PASS."""
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                },
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_bare_action_wildcard_pair_is_left_to_admin_checks(self):
        """`Action: "*:*"` must PASS: it is check_admin_access's finding, not this one.

        The only bare-wildcard fixture was `"*"`, which the `separator != ":"` clause alone
        satisfies, so the `service == "*" and operation == "*"` clause was load-bearing with zero
        coverage -- deleting it left all tests green while flipping this policy to FAIL, emitting
        exactly the duplicate finding the docstring says must not be emitted.
        """
        policy = _policy([{"Effect": "Allow", "Action": "*:*", "Resource": "*"}])
        assert _run([policy])[0].status == "PASS"

    def test_a_single_field_pattern_is_not_an_arn(self):
        """A one-field pattern with a star reaches no workload identity, so PASS.

        `myprefix*` matches no ARN at all -- an ARN starts with the literal "arn" -- but it is short
        and starred, so it takes the short branch. That branch's first-field guard is what rejects
        it; deleting the guard left 55 tests green while flipping this to FAIL. The six-field
        branch's equivalent guard was already covered, so only the short one was unprotected.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "myprefix*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize("deny_action", ["*", "*:*"])
    def test_a_deny_of_every_action_clears_the_finding(self, deny_action):
        """A Deny of EVERY action on "*" removes these operations, so the policy must PASS.

        Both spellings reported FAIL at high severity on a policy that grants nothing -- prowler's
        own effective-action resolver agrees the operation is not granted. The cause is that the
        Deny side reused the Allow side's reader, which deliberately skips a bare "*" and "*:*" so
        this check does not duplicate the administrative-privileges checks. On the Deny side that
        exclusion inverts: skipping the broadest possible Deny credits nothing.

        It also contradicted this check's own published Notes, which say an unconditional Deny of
        the operation on Resource "*" clears the finding. The Allow-side guard is untouched.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "*",
                },
                {"Effect": "Deny", "Action": deny_action, "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_a_deny_of_every_action_in_another_service_does_not_clear_the_finding(self):
        """The guard on the fix above: a Deny of every action in a DIFFERENT service clears nothing.

        `s3:*` removes no AgentCore operation, so widening the Deny-side reader to credit any
        wildcard would have cleared this policy too. It must still FAIL.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "*",
                },
                {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_listing_the_wildcard_among_other_resources_clears_the_finding(self):
        """A Deny whose Resource list contains "*" denies everything in it.

        The collector tests the list with any(), not all(): one "*" entry is sufficient,
        because IAM evaluates each Resource independently. Under all() this policy would
        stop clearing the finding and report a false FAIL. Every other Deny fixture here
        uses a single Resource value, so nothing else distinguishes the two.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": ["*", DIRECTORY_ARN],
                },
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_conditional_deny_does_not_clear_the_finding(self):
        """A CONDITIONAL Deny must not clear the finding: it only bites when the condition holds.

        The Allow still stands for every request outside the condition, so the capability remains.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "agents"}},
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_scoped_to_one_directory_does_not_clear_the_finding(self):
        """A Deny naming one directory does not answer an Allow that reaches every other one.

        This is AWS's own recommended Deny shape, so treating it as sufficient would clear a
        finding on a policy that is still broad.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyForUserIdAccess",
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": DIRECTORY_ARN,
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_of_a_different_operation_does_not_clear_the_finding(self):
        """A Deny removes only the operation it names; the rest of the wildcard Allow still FAILs.

        Asserted in both directions: the denied operation must be absent from the finding and the
        still-granted one present, so a Deny applied too widely or too narrowly both fail.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkload*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "*",
                },
            ]
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert "ForUserId" not in result[0].status_extended
        assert "GetWorkloadAccessTokenForJWT" in result[0].status_extended

    def test_deny_only_policy_passes(self):
        """A policy containing only a Deny grants nothing, so it must PASS."""
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_conditional_deny_only_policy_passes(self):
        """A conditional Deny alone still grants nothing, so it must PASS.

        Reading Effect is what stops the statement being treated as though it allowed the action.
        """
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "agents"}},
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_single_statement_dict_is_evaluated(self):
        """A Statement given as a single dict rather than a list is still evaluated.

        IAM accepts both shapes, so a check reading only lists would silently skip the policy.
        """
        policy = _policy(None)
        policy.document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                "Resource": "*",
            },
        }
        assert _run([policy])[0].status == "FAIL"

    def test_malformed_statements_do_not_raise(self):
        """Malformed statements must not raise, and must not mask the real grant beside them.

        A bare string, non-string actions, and an action with no colon all coexist with one genuine
        wildcard grant, so the FAIL proves the parser survived rather than short-circuited.
        """
        policy = _policy(
            [
                "not-a-statement",
                {"Effect": "Allow", "Action": [None, 7], "Resource": [None]},
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                    "Resource": "*",
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_action_of_another_service_matching_the_name_passes(self):
        """bedrock:GetWorkloadAccessToken is a different service, so it must PASS.

        Only the bedrock-agentcore prefix is read; matching on the operation name alone would
        report a policy for a service that has no such action.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": "bedrock:GetWorkloadAccessToken",
                    "Resource": "*",
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_every_policy_gets_one_finding(self):
        """Three policies get one report each, judged on their own document.

        FAIL, PASS and MANUAL from one run, so a check reporting only the first policy or carrying
        a verdict between them would not produce this mapping.
        """
        policies = [
            _policy(
                [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                        "Resource": "*",
                    }
                ],
                name="broad",
            ),
            _policy(
                [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                        "Resource": WORKLOAD_ARN,
                    }
                ],
                name="scoped",
            ),
            _policy([], name="unreadable", document_present=False),
        ]
        result = _run(policies)
        assert {report.resource_id: report.status for report in result} == {
            "broad": "FAIL",
            "scoped": "PASS",
            "unreadable": "MANUAL",
        }


class Test_iam_policy_no_agentcore_workload_access_token_wildcard_notaction:
    """NotAction under Effect Allow is IAM-valid and grants everything it does not list."""

    def test_notaction_allow_statement_is_manual(self):
        """The check reads only Action, so a NotAction statement looked like no grant at all.

        `{"Effect": "Allow", "NotAction": ["s3:*"], "Resource": "*"}` grants every action
        except S3 -- including the ones this check exists to find -- while carrying no Action
        key. IAM Access Analyzer ValidatePolicy accepts the shape, so it is reachable in a
        stored policy. Inverting NotAction correctly means resolving it against the whole
        action namespace and its interaction with Resource and NotResource, which is more
        than this check can claim, so it reports the policy as unevaluated instead.
        """
        policy = _policy(
            [{"Effect": "Allow", "NotAction": ["s3:*"], "Resource": "*"}],
            name="notaction-policy",
        )
        result = _run([policy])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "NotAction" in result[0].status_extended
