from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ROLE_NAME = "test-agentcore-role"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"

SCOPED_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
            "Resource": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/example-runtime-id",
        }
    ],
}
WILDCARD_ACTION_ALL_RESOURCES_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}
    ],
}
REGISTRY_WILDCARD_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["agent-registry:*"], "Resource": ["*"]}
    ],
}
WILDCARD_ACTION_SCOPED_RESOURCE_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:*",
            "Resource": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/example-runtime-id",
        }
    ],
}
DENY_WILDCARD_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetGateway", "Resource": "*"},
        {"Effect": "Deny", "Action": "bedrock-agentcore:*", "Resource": "*"},
    ],
}
UNRELATED_SERVICE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
# A SCOPED AgentCore grant beside an unrelated one. Scoped matters: when a document grants
# a whole namespace the check returns relevant=True unconditionally, so only a scoped grant
# lets the any()/all() over the Allow statements decide anything.
SCOPED_AGENTCORE_BESIDE_UNRELATED_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
            "Resource": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/example-runtime-id",
        },
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    ],
}
BARE_DICT_STATEMENT_DOC = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "bedrock-agentcore:*",
        "Resource": "*",
    },
}
# Action "*" is a strict superset of bedrock-agentcore:*, so an
# AdministratorAccess-shaped policy grants full AgentCore access too.
ADMIN_ACTION_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
SERVICE_AND_ACTION_WILDCARD_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*:*", "Resource": "*"}],
}
# An Allow with NotAction grants every action it does not exclude.
NOT_ACTION_UNRELATED_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": "*"}],
}
# Excluding the namespace leaves none of it granted.
NOT_ACTION_EXCLUDING_AGENTCORE_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "NotAction": ["bedrock-agentcore:*", "agent-registry:*"],
            "Resource": "*",
        }
    ],
}
# IAM matches action names case-insensitively.
UPPERCASE_WILDCARD_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "BEDROCK-AGENTCORE:*", "Resource": "*"}
    ],
}
# An intra-action glob reaches only part of the namespace, so it is not full
# access however broad it looks.
INTRA_ACTION_GLOB_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:Invoke*", "Resource": "*"}
    ],
}
# Enumerating every registry action reaches the whole agent-registry namespace
# without ever writing a wildcard.
REGISTRY_ENUMERATED_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "agent-registry:CreateRegistry",
                "agent-registry:CreateRegistryRecord",
                "agent-registry:DeleteRegistry",
                "agent-registry:DeleteRegistryRecord",
                "agent-registry:DeleteResourcePolicy",
                "agent-registry:GetDiscoverableRegistryRecord",
                "agent-registry:GetRegistry",
                "agent-registry:GetRegistryRecord",
                "agent-registry:GetResourcePolicy",
                "agent-registry:InvokeRegistryMcp",
                "agent-registry:ListDiscoverableRegistryRecords",
                "agent-registry:ListRegistries",
                "agent-registry:ListRegistryRecords",
                "agent-registry:ListTagsForResource",
                "agent-registry:PutResourcePolicy",
                "agent-registry:SearchDiscoverableRegistryRecords",
                "agent-registry:SubmitRegistryRecordForApproval",
                "agent-registry:TagResource",
                "agent-registry:UntagResource",
                "agent-registry:UpdateRegistry",
                "agent-registry:UpdateRegistryRecord",
                "agent-registry:UpdateRegistryRecordStatus",
            ],
            "Resource": "*",
        }
    ],
}
# A registry read-only grant is scoped, and must not be read as full access just
# because the namespace is involved.
REGISTRY_READ_ONLY_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["agent-registry:GetRegistry", "agent-registry:ListRegistries"],
            "Resource": "*",
        }
    ],
}
# A Deny on the registry namespace cancels the wildcard Allow above it.
REGISTRY_WILDCARD_THEN_DENY_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "agent-registry:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "agent-registry:DeleteRegistry", "Resource": "*"},
    ],
}
# Action "*" scoped to one ARN is not full access on all resources.
ADMIN_ACTION_SCOPED_RESOURCE_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/example-runtime-id",
        }
    ],
}


# Distinguishes "caller passed nothing" from "caller passed None". Without it the helper
# coalesced None to [], which left the unreadable-inventory branch unreachable from the tests,
# so nothing here would have caught that branch reporting PASS instead of MANUAL.
_UNSET = object()


class _Role:
    """Minimal stand-in for the IAM service Role model."""

    def __init__(self, attached_policies=None, inline_policies=None, name=ROLE_NAME):
        self.name = name
        self.arn = ROLE_ARN
        self.attached_policies = attached_policies or []
        self.inline_policies = inline_policies or []


class _Policy:
    """Minimal stand-in for the IAM service Policy model."""

    def __init__(self, document):
        self.document = document


class Test_bedrockagentcore_full_access_policy_attached:
    """Unit tests for the bedrockagentcore_full_access_policy_attached check."""

    def _run(self, roles=_UNSET, policies=None):
        """Import the check under a stub IAM client and execute."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = mock.MagicMock()
        iam_client.roles = [] if roles is _UNSET else roles
        iam_client.policies = policies if policies is not None else {}
        iam_client.region = AWS_REGION_US_EAST_1

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached import (
                bedrockagentcore_full_access_policy_attached,
            )

            return bedrockagentcore_full_access_policy_attached().execute()

    @mock_aws
    def test_no_resources(self):
        """No roles means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock_aws
    def test_roles_absent_from_inventory(self):
        """An unreadable IAM inventory is MANUAL, not an account with no roles.

        ListRoles being denied leaves the inventory unknown. Reporting nothing would
        read as a clean account, so the check emits one account-level MANUAL.
        """
        result = self._run(roles=None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "IAM roles could not be listed, so this check could not be evaluated; verify manually that no role grants full access to Bedrock AgentCore."
        )

    @mock_aws
    def test_role_without_agentcore_grant_is_skipped(self):
        """A role with no AgentCore action at all is not this check's business."""
        result = self._run(
            roles=[_Role(inline_policies=["unrelated"])],
            policies={f"{ROLE_ARN}:policy/unrelated": _Policy(UNRELATED_SERVICE_DOC)},
        )
        assert result == []

    @mock_aws
    def test_scoped_agentcore_grant_passes(self):
        """An action- and resource-scoped AgentCore grant is compliant."""
        result = self._run(
            roles=[_Role(inline_policies=["scoped"])],
            policies={f"{ROLE_ARN}:policy/scoped": _Policy(SCOPED_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == ROLE_NAME
        assert result[0].resource_arn == ROLE_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_wildcard_action_on_scoped_resource_passes(self):
        """bedrock-agentcore:* limited to one runtime ARN is not full access."""
        result = self._run(
            roles=[_Role(inline_policies=["scopedresource"])],
            policies={
                f"{ROLE_ARN}:policy/scopedresource": _Policy(
                    WILDCARD_ACTION_SCOPED_RESOURCE_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_deny_wildcard_statement_is_not_a_grant(self):
        """A Deny on bedrock-agentcore:* grants nothing, so it must not FAIL."""
        result = self._run(
            roles=[_Role(inline_policies=["denywildcard"])],
            policies={f"{ROLE_ARN}:policy/denywildcard": _Policy(DENY_WILDCARD_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_bedrockagentcore_full_access_managed_policy_fails(self):
        """The AWS-managed full-access policy is flagged by ARN, without a document."""
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess",
                            "PolicyName": "BedrockAgentCoreFullAccess",
                        }
                    ]
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        # The bare PolicyName, not the ARN. Asserting the substring alone cannot tell the
        # two apart, because the ARN ends with the same name, so an equality assertion is
        # what pins the `PolicyName or PolicyArn` fallback.
        # Wording moved when the managed grant started flowing through the aggregated role
        # evaluation rather than being reported on sight -- the finding is now phrased by the same
        # code path as a document-based one. The assertion still pins what matters: the bare
        # PolicyName appears and the ARN does not.
        assert (
            "AWS-managed policy BedrockAgentCoreFullAccess allows"
            in result[0].status_extended
        )
        assert "arn:aws:iam::aws:policy/" not in result[0].status_extended

    @mock_aws
    def test_agent_registry_full_access_managed_policy_fails(self):
        """AgentRegistryFullAccess is a SEPARATE AWS-managed policy, not a rename, and must fail too.

        It grants agent-registry:* rather than bedrock-agentcore:*, and both policies remain
        attachable, so a role holding either has service-wide admin over an AgentCore surface.
        """
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/AgentRegistryFullAccess",
                            "PolicyName": "AgentRegistryFullAccess",
                        }
                    ]
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AgentRegistryFullAccess" in result[0].status_extended

    @mock_aws
    def test_scoped_agentcore_grant_beside_an_unrelated_one_is_still_evaluated(self):
        """A policy is relevant if ANY Allow touches AgentCore, not only if all do.

        `relevant` is computed with any() over the Allow statements, and it is what turns the
        unreadable-document message from "may grant" into "grants". Under all() a document
        that scopes an AgentCore action alongside any unrelated Allow -- the ordinary shape of
        a real policy -- stops counting as an AgentCore role, and the finding understates what
        is known about it. Every other multi-statement fixture here has AgentCore in every
        Allow, so nothing distinguished the two operators.
        """
        result = self._run(
            roles=[_Role(inline_policies=["mixed", "missing"])],
            policies={
                f"{ROLE_ARN}:policy/mixed": _Policy(
                    SCOPED_AGENTCORE_BESIDE_UNRELATED_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "grants Bedrock AgentCore access" in result[0].status_extended
        assert "may grant" not in result[0].status_extended

    @mock_aws
    def test_inline_wildcard_action_on_all_resources_fails(self):
        """bedrock-agentcore:* on * is full access however it is written."""
        result = self._run(
            roles=[_Role(inline_policies=["wildcard"])],
            policies={
                f"{ROLE_ARN}:policy/wildcard": _Policy(
                    WILDCARD_ACTION_ALL_RESOURCES_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "bedrock-agentcore:*" in result[0].status_extended
        assert "on all resources" in result[0].status_extended

    @mock_aws
    def test_customer_managed_registry_wildcard_fails(self):
        """agent-registry:* on * is the registry namespace equivalent."""
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/example-registry-policy",
                            "PolicyName": "example-registry-policy",
                        }
                    ]
                )
            ],
            policies={
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/example-registry-policy": _Policy(
                    REGISTRY_WILDCARD_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "agent-registry:*" in result[0].status_extended

    @mock_aws
    def test_statement_as_bare_dict_is_normalised(self):
        """A dict Statement must be evaluated, not skipped."""
        result = self._run(
            roles=[_Role(inline_policies=["baredict"])],
            policies={f"{ROLE_ARN}:policy/baredict": _Policy(BARE_DICT_STATEMENT_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_admin_action_wildcard_fails(self):
        """Action "*" is a superset of bedrock-agentcore:*, so it is full access."""
        result = self._run(
            roles=[_Role(inline_policies=["admin"])],
            policies={f"{ROLE_ARN}:policy/admin": _Policy(ADMIN_ACTION_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "bedrock-agentcore:*" in result[0].status_extended
        assert "on all resources" in result[0].status_extended

    @mock_aws
    def test_service_and_action_wildcard_fails(self):
        """Action "*:*" reaches every AgentCore action just as "*" does."""
        result = self._run(
            roles=[_Role(inline_policies=["starstar"])],
            policies={
                f"{ROLE_ARN}:policy/starstar": _Policy(SERVICE_AND_ACTION_WILDCARD_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_not_action_excluding_unrelated_action_fails(self):
        """An Allow with NotAction grants everything it does not exclude."""
        result = self._run(
            roles=[_Role(inline_policies=["notaction"])],
            policies={
                f"{ROLE_ARN}:policy/notaction": _Policy(NOT_ACTION_UNRELATED_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_not_action_excluding_agentcore_is_skipped(self):
        """Excluding both namespaces grants none of them, so there is nothing to report."""
        result = self._run(
            roles=[_Role(inline_policies=["excluded"])],
            policies={
                f"{ROLE_ARN}:policy/excluded": _Policy(
                    NOT_ACTION_EXCLUDING_AGENTCORE_DOC
                )
            },
        )
        assert result == []

    @mock_aws
    def test_uppercase_action_wildcard_fails(self):
        """IAM matches action names case-insensitively, so casing must still FAIL."""
        result = self._run(
            roles=[_Role(inline_policies=["upper"])],
            policies={f"{ROLE_ARN}:policy/upper": _Policy(UPPERCASE_WILDCARD_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_intra_action_glob_passes(self):
        """bedrock-agentcore:Invoke* leaves the control-plane actions ungranted."""
        result = self._run(
            roles=[_Role(inline_policies=["invokeglob"])],
            policies={f"{ROLE_ARN}:policy/invokeglob": _Policy(INTRA_ACTION_GLOB_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_admin_action_on_scoped_resource_passes(self):
        """Action "*" limited to one runtime ARN is not full access on all resources."""
        result = self._run(
            roles=[_Role(inline_policies=["scopedadmin"])],
            policies={
                f"{ROLE_ARN}:policy/scopedadmin": _Policy(
                    ADMIN_ACTION_SCOPED_RESOURCE_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_enumerated_registry_namespace_fails(self):
        """Listing every registry action reaches the namespace without a wildcard."""
        result = self._run(
            roles=[_Role(inline_policies=["enumerated"])],
            policies={
                f"{ROLE_ARN}:policy/enumerated": _Policy(REGISTRY_ENUMERATED_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "agent-registry:*" in result[0].status_extended

    @mock_aws
    def test_registry_read_only_grant_passes(self):
        """A scoped registry grant must not be read as full access."""
        result = self._run(
            roles=[_Role(inline_policies=["registryread"])],
            policies={
                f"{ROLE_ARN}:policy/registryread": _Policy(REGISTRY_READ_ONLY_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_registry_wildcard_cancelled_by_deny_passes(self):
        """A Deny inside the namespace means the wildcard no longer reaches all of it."""
        result = self._run(
            roles=[_Role(inline_policies=["registrydeny"])],
            policies={
                f"{ROLE_ARN}:policy/registrydeny": _Policy(
                    REGISTRY_WILDCARD_THEN_DENY_DOC
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_unresolvable_policy_document_is_manual_not_pass(self):
        """An AgentCore role with an unreadable second policy must not PASS."""
        result = self._run(
            roles=[_Role(inline_policies=["scoped", "missing"])],
            policies={f"{ROLE_ARN}:policy/scoped": _Policy(SCOPED_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert "inline policy missing" in result[0].status_extended

    @mock_aws
    def test_an_established_violation_is_not_downgraded_by_an_unreadable_sibling(self):
        """A proven full-access grant stays FAIL even when another document could not be read.

        This pins the ORDER of the two branches, which was previously unpinned: a review proposed
        moving `unresolved` ahead of `violations`, on the grounds that the unreadable document could
        hold a Deny cancelling the grant. That inverts the caution this check needs.

        `violations` is only non-empty when a document that WAS read established the grant, so the
        finding is evidenced. `unresolved` only raises the possibility that something unread cancels
        it -- and to cancel a namespace-wide grant, the unread document would have to Deny the whole
        namespace on every resource; anything narrower leaves the grant partly intact and FAIL stays
        correct. MANUAL is not a failure status, so reordering would drop a certain true positive out
        of the failure count in exchange for avoiding an unlikely false positive.

        The sibling check cloudtrail_agentcore_data_events_enabled resolves the same shape the same
        way: a stopped trail does not downgrade an established AgentCore FAIL.
        """
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess",
                            "PolicyName": "BedrockAgentCoreFullAccess",
                        }
                    ],
                    inline_policies=["missing"],
                )
            ],
            policies={},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "an established full-access grant must not be downgraded to MANUAL by an unreadable "
            f"sibling policy; got {result[0].status}: {result[0].status_extended}"
        )
        assert "BedrockAgentCoreFullAccess" in result[0].status_extended
        # And the FAIL text must not claim the unreadable document was assessed.
        assert "could not be retrieved" not in result[0].status_extended

    @mock_aws
    def test_a_deny_in_another_policy_overrides_the_wildcard_allow(self):
        """IAM evaluates a role's policies together, so a Deny anywhere beats an Allow anywhere.

        This is the case that made the check wrong. It used to evaluate each attached and inline
        document separately and combine the verdicts, so a namespace-wide Allow in one policy stayed
        a FAIL even though a second policy denied the same namespace -- reporting a role as holding
        full access when IAM would refuse every one of those calls. The statements are now aggregated
        before evaluation, which is what makes check_full_service_access's Deny subtraction real.
        """
        result = self._run(
            roles=[_Role(inline_policies=["allow-all", "deny-all"])],
            policies={
                f"{ROLE_ARN}:policy/allow-all": _Policy(
                    WILDCARD_ACTION_ALL_RESOURCES_DOC
                ),
                f"{ROLE_ARN}:policy/deny-all": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock-agentcore:*",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a Deny in a sibling policy must override the wildcard Allow; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_in_a_managed_policy_overrides_an_inline_allow(self):
        """The aggregation must span attached and inline policies, not just one kind."""
        managed_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/deny-agentcore"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": managed_arn, "PolicyName": "deny-agentcore"}
                    ],
                    inline_policies=["allow-all"],
                )
            ],
            policies={
                managed_arn: _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock-agentcore:*",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
                f"{ROLE_ARN}:policy/allow-all": _Policy(
                    WILDCARD_ACTION_ALL_RESOURCES_DOC
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_a_customer_policy_whose_name_ends_the_same_way_is_not_a_finding(self):
        """Only AWS-managed ARNs may be matched by name.

        FULL_ACCESS_POLICY_SUFFIXES exists because the two AWS-managed documents scope their
        Resource and so cannot be caught by reading them. Matching the name on ANY ARN turned a
        customer-managed ``TeamBedrockAgentCoreFullAccess`` into a FAIL without the check ever
        reading the document -- here that document grants one scoped action, so the role is compliant
        and must PASS. The guard requires the ``:iam::aws:policy/`` segment and an exact basename.
        """
        customer_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/TeamBedrockAgentCoreFullAccess"
        )
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": customer_arn,
                            "PolicyName": "TeamBedrockAgentCoreFullAccess",
                        }
                    ]
                )
            ],
            policies={customer_arn: _Policy(SCOPED_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a customer-managed policy whose name merely ends with an AWS-managed name must be "
            f"evaluated by its document; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_the_aws_managed_policy_is_still_matched_by_name(self):
        """The negative control for the guard above: the real AWS-managed ARN must still FAIL."""
        managed_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": managed_arn,
                            "PolicyName": "BedrockAgentCoreFullAccess",
                        }
                    ]
                )
            ],
            policies={},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "BedrockAgentCoreFullAccess" in result[0].status_extended

    @mock_aws
    def test_the_aws_managed_policy_is_matched_in_other_partitions(self):
        """GovCloud and China ARNs carry a different partition; the guard must not be prefix-based."""
        for partition in ("aws-us-gov", "aws-cn"):
            managed_arn = f"arn:{partition}:iam::aws:policy/AgentRegistryFullAccess"
            result = self._run(
                roles=[
                    _Role(
                        attached_policies=[
                            {
                                "PolicyArn": managed_arn,
                                "PolicyName": "AgentRegistryFullAccess",
                            }
                        ]
                    )
                ],
                policies={},
            )
            assert len(result) == 1, partition
            assert result[0].status == "FAIL", partition

    @mock_aws
    def test_a_grant_missing_one_registry_action_is_not_full_access(self):
        """Enumerating all but one action is scoped access, so the role must PASS.

        This is the regression case for the action inventory itself. `AGENT_REGISTRY_ACTIONS` is the
        target that "grants every action in the namespace" is measured against, so an INCOMPLETE
        inventory shrinks the target and lets a partial grant clear it — reporting FAIL for a role
        that does not in fact hold the whole namespace. The inventory was six actions short: the
        three tagging actions and the three permission-only resource-policy ones, of which
        `PutResourcePolicy` is how cross-account access to a registry is granted.

        Dropping any single action must therefore be enough to make this PASS.
        """
        actions = [
            a
            for a in REGISTRY_ENUMERATED_DOC["Statement"][0]["Action"]
            if a != "agent-registry:PutResourcePolicy"
        ]
        assert (
            len(actions) == len(REGISTRY_ENUMERATED_DOC["Statement"][0]["Action"]) - 1
        )
        result = self._run(
            roles=[_Role(inline_policies=["almost-all"])],
            policies={
                f"{ROLE_ARN}:policy/almost-all": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": actions, "Resource": "*"}
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a grant missing one namespace action is not full access; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_overrides_the_named_aws_managed_policy(self):
        """An explicit Deny beats the AWS-managed grant, which the name match alone cannot see.

        The name match is how this check establishes that BedrockAgentCoreFullAccess grants the whole
        namespace — its real document scopes its Resource, so reading it proves nothing. But an Allow
        established by name is still only an Allow, and IAM lets an explicit Deny anywhere on the role
        override it. Reporting the managed policy on sight therefore FAILed a role that cannot call the
        service at all.

        The grant now joins the aggregated role evaluation as a synthetic
        `Allow bedrock-agentcore:* on *`, so the same Deny subtraction that covers document-based
        grants covers this one.
        """
        managed_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": managed_arn,
                            "PolicyName": "BedrockAgentCoreFullAccess",
                        }
                    ],
                    inline_policies=["deny-all"],
                )
            ],
            policies={
                f"{ROLE_ARN}:policy/deny-all": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock-agentcore:*",
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "an explicit Deny of the namespace must override the AWS-managed grant; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_registry_deny_does_not_excuse_the_agentcore_managed_policy(self):
        """The Deny must match the namespace the managed policy actually grants.

        `AgentRegistryFullAccess` grants `agent-registry:*` and `BedrockAgentCoreFullAccess` grants
        `bedrock-agentcore:*`, so denying the wrong one leaves the grant standing. Without this the
        previous case could pass for the wrong reason — any Deny at all suppressing the finding.
        """
        managed_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": managed_arn,
                            "PolicyName": "BedrockAgentCoreFullAccess",
                        }
                    ],
                    inline_policies=["deny-registry"],
                )
            ],
            policies={
                f"{ROLE_ARN}:policy/deny-registry": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_a_deny_naming_no_real_action_cannot_excuse_the_namespace(self):
        """An Action pattern IAM reads as literal text must not be expanded into a real deny.

        Action matching was `fnmatch`, which implements `[seq]` character classes; IAM honours only
        `*` and `?` and treats every other character literally. `agent-registry:[Dd]eleteRegistry` is
        therefore the name of an action that does not exist, and the statement denies nothing.

        This was a FALSE PASS rather than noise, because one helper resolves both effects and the
        verdict is `AGENT_REGISTRY_ACTIONS <= (allowed - denied)`. Over-matching in a DENY inflates
        `denied`, so the subset test fails and a role holding the entire namespace is reported as
        holding scoped access. Measured: PASS, on a role granting `agent-registry:*`.
        """
        result = self._run(
            roles=[_Role(inline_policies=["inert-deny"])],
            policies={
                f"{ROLE_ARN}:policy/inert-deny": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            },
                            {
                                "Effect": "Deny",
                                "Action": "agent-registry:[Dd]eleteRegistry",
                                "Resource": "*",
                            },
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny naming an action that cannot exist must not excuse agent-registry:*; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_single_character_action_wildcard_is_still_honoured(self):
        """The counterweight: `?` is a real IAM Action metacharacter and must keep working.

        Without this, "escape everything" would pass the test above while turning every `?` pattern
        into a literal — silently narrowing both grants and denies.
        """
        result = self._run(
            roles=[_Role(inline_policies=["wildcard-then-deny"])],
            policies={
                f"{ROLE_ARN}:policy/wildcard-then-deny": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            },
                            {
                                # "DeleteRegistr?" reaches DeleteRegistry only if `?` consumes the
                                # final character, so this Deny does remove a real action.
                                "Effect": "Deny",
                                "Action": "agent-registry:DeleteRegistr?",
                                "Resource": "*",
                            },
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "`?` must match one character, so this Deny removes DeleteRegistry and the namespace is "
            f"no longer wholly granted; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_non_canonically_spelled_deny_still_subtracts_in_the_registry_branch(
        self,
    ):
        """Effect must have ONE reading across the whole aggregated statement list.

        `statements_with_only_unconditional_denies` normalises Effect before deciding what to keep, so
        it kept this Deny. The registry branch compared against the exact string `"Deny"`, so it
        skipped the same statement -- the Deny never reached `denied`, `agent-registry:*` looked wholly
        granted, and the role reported FAIL. IAM stores the canonical spellings, so the two readings
        were latent rather than observed; this pins them together.
        """
        result = self._run(
            roles=[_Role(inline_policies=["wildcard-then-odd-case-deny"])],
            policies={
                f"{ROLE_ARN}:policy/wildcard-then-odd-case-deny": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            },
                            {
                                "Effect": " deny ",
                                "Action": "agent-registry:DeleteRegistry",
                                "Resource": "*",
                            },
                        ],
                    }
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "the Deny the keep-filter honoured must also subtract here, so the namespace is not "
            f"wholly granted; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_non_canonically_spelled_allow_still_brings_the_role_into_scope(self):
        """The same divergence on the Allow side of `_evaluate_document`.

        `relevant` decided whether the role is an AgentCore role at all, and comparing against the
        exact string `"Allow"` made a non-canonically spelled grant invisible -- the role was skipped
        with no finding rather than reported as scoped.
        """
        result = self._run(
            roles=[_Role(inline_policies=["odd-case-scoped-allow"])],
            policies={
                f"{ROLE_ARN}:policy/odd-case-scoped-allow": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "allow",
                                "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
                                "Resource": f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/example-runtime-id",
                            }
                        ],
                    }
                )
            },
        )
        assert len(result) == 1, (
            "a scoped grant spelled `allow` is still an AgentCore grant and the role must be "
            f"evaluated, not skipped; got {result}"
        )
        assert result[0].status == "PASS", (
            f"the grant is scoped, so it is not full access; got {result[0].status}: "
            f"{result[0].status_extended}"
        )

    def _matcher(self):
        """The Action matcher, imported under the same stubs `_run` uses.

        Importing the check module constructs its iam_client, so a bare import inside a test
        raises AttributeError in the real service layer. Both assertions below are about a pure
        helper, but the module boundary still has to be crossed the same way.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached.iam_client",
                new=mock.MagicMock(),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached import (
                _action_matches,
            )

            return _action_matches

    @mock_aws
    def test_a_wildcard_dense_action_pattern_does_not_stall_the_scan(self):
        """An Action pattern is attacker-writable text, so matching it must not backtrack.

        The first IAM-correct version of this helper translated every `*` into `.*` and called
        `re.fullmatch`. That backtracks catastrophically: measured 0.030s at a 44-character
        pattern, 1.892s at 56, 7.576s at 60, and no result inside 30s at 64. A hang is worse than
        a raised exception, because the bare `except Exception` in check.py cannot catch it -- the
        scan simply never finishes. The `fnmatch` this helper replaced did NOT have the problem,
        since `fnmatch.translate` emits atomic groups, so dropping fnmatch for IAM correctness had
        to supply its own bound.
        """
        from time import monotonic

        _action_matches = self._matcher()

        # 512 characters, eight times the length that used to hang. The action must NOT match, or
        # the old implementation short-circuits and the test proves nothing: the pattern ends in a
        # literal `a`, so an action ending in `b` cannot match however many `a` it contains, and
        # every backtracking path has to be explored before that is discovered. Verified against a
        # full DP reference over 1.3M pattern/text pairs; measured HUNG >10s on the old code and
        # 0.00002s on this one.
        pattern = "*a" * 256
        action = "agent-registry:" + "ab" * 256

        started = monotonic()
        matched = _action_matches(pattern, action)
        elapsed = monotonic() - started

        assert matched is False, (
            "the pattern requires 256 literal 'a' separated by wildcards and the action has no "
            "such structure, so it must not match"
        )
        assert elapsed < 1.0, (
            f"matching a 512-character wildcard-dense pattern took {elapsed:.3f}s. This helper "
            "must stay bounded by the product of the two lengths; a backtracking implementation "
            "lets any principal who can write a policy stall the whole scan."
        )

    @mock_aws
    def test_bracket_characters_stay_literal_in_an_action_pattern(self):
        """The defect that made this helper stop using fnmatch, kept as a regression."""
        _action_matches = self._matcher()

        assert (
            _action_matches(
                "agent-registry:[dd]eleteregistry", "agent-registry:deleteregistry"
            )
            is False
        ), (
            "IAM honours only * and ?, so a bracket is a literal character and this pattern "
            "names an action that does not exist -- it must match nothing"
        )
        assert (
            _action_matches("agent-registry:*", "agent-registry:deleteregistry") is True
        ), "a trailing wildcard must still reach every action in the namespace"

    @mock_aws
    def test_the_finding_text_does_not_depend_on_the_order_iam_returned_the_policies(
        self,
    ):
        """One role must not render as two different findings across scans.

        `ListAttachedRolePolicies` and `ListRolePolicies` document no ordering, so the two loops
        that build the contributing-policy list can visit the same role's policies in either order.
        Before the sort, that produced "managed policy A and managed policy B together" on one scan
        and "...B and ...A together" on the next -- the same state reported as two findings, which
        is exactly the defect fixed in the delegated-administrator listing.
        """
        wildcard = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}
            ],
        }
        scoped = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "bedrock-agentcore:InvokeAgentRuntime",
                    "Resource": "*",
                }
            ],
        }
        arn_a = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/aaa-first"
        arn_z = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/zzz-second"
        policies = {arn_a: _Policy(scoped), arn_z: _Policy(wildcard)}
        forward = [
            {"PolicyArn": arn_a, "PolicyName": "aaa-first"},
            {"PolicyArn": arn_z, "PolicyName": "zzz-second"},
        ]

        first = self._run(roles=[_Role(attached_policies=forward)], policies=policies)
        second = self._run(
            roles=[_Role(attached_policies=list(reversed(forward)))], policies=policies
        )

        assert (
            len(first) == 1 and len(second) == 1
        ), f"both orderings must evaluate the one role; got {len(first)} and {len(second)}"
        assert first[0].status == second[0].status, (
            f"the verdict must not depend on ordering; got {first[0].status} then "
            f"{second[0].status}"
        )
        assert first[0].status_extended == second[0].status_extended, (
            "the same role and the same policies produced two different finding texts purely "
            f"because IAM returned them in a different order:\n  {first[0].status_extended}\n  "
            f"{second[0].status_extended}"
        )
