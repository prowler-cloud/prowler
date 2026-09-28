import os
import pathlib
from unittest import mock

import yaml
from moto import mock_aws

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import LogGroup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_agentcore_data_protection_policy_enabled.cloudwatch_log_group_agentcore_data_protection_policy_enabled"

RUNTIME_LOG_GROUP = "/aws/bedrock-agentcore/runtimes/my_agent-1a2b3c4d5e"
VENDED_LOG_GROUP = (
    "/aws/vendedlogs/bedrock-agentcore/memory/APPLICATION_LOGS/my-memory-1a2b3c"
)


def log_group(name, data_protection_status=None, inherited_properties=None):
    """Build a LogGroup carrying the two fields this check reads.

    Both default to the state DescribeLogGroups reports for a log group that has never had a data
    protection policy: dataProtectionStatus absent, and no inherited properties.
    """
    return LogGroup(
        arn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{name}:*",
        name=name,
        retention_days=365,
        never_expire=False,
        kms_id=None,
        creation_time=1700000000000,
        data_protection_status=data_protection_status,
        inherited_properties=inherited_properties or [],
        region=AWS_REGION_US_EAST_1,
    )


def run_check(log_groups, audit_config=None):
    """Drive the check over a fixed inventory.

    The inventory is set on the service object rather than served through a
    patched _make_api_call: DescribeLogGroups -> LogGroup field mapping and its
    pagination are covered in cloudwatch_service_test.py, and patching a global
    here made these tests sensitive to the order they run in.
    """
    from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1],
        audit_config={} if audit_config is None else audit_config,
    )

    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ):
        logs_client = Logs(aws_provider)
        logs_client.log_groups = (
            None if log_groups is None else {group.arn: group for group in log_groups}
        )

        with mock.patch(f"{CHECK_MODULE}.logs_client", new=logs_client):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_agentcore_data_protection_policy_enabled.cloudwatch_log_group_agentcore_data_protection_policy_enabled import (
                cloudwatch_log_group_agentcore_data_protection_policy_enabled,
            )

            return (
                cloudwatch_log_group_agentcore_data_protection_policy_enabled().execute()
            )


class Test_cloudwatch_log_group_agentcore_data_protection_policy_enabled:
    """Tests for the cloudwatch_log_group_agentcore_data_protection_policy_enabled check."""

    @mock_aws
    def test_no_log_groups(self):
        """An account with no log groups at all must produce no findings.

        An empty inventory was read successfully, so it is not the MANUAL case; there is simply no
        resource to make a claim about.
        """
        assert run_check([]) == []

    @mock_aws
    def test_non_agentcore_log_group_is_out_of_scope(self):
        """Log groups outside the AgentCore prefixes must produce no findings.

        Asserting a data protection policy on every log group in the account would bury the
        AgentCore ones. The lookalike name is the case that matters: the prefix must be matched with
        its trailing slash, or /aws/bedrock-agentcore-lookalike/ is pulled into scope.
        """
        results = run_check(
            [
                log_group("/aws/lambda/unrelated-function"),
                log_group("aws/spans"),
                log_group("/aws/bedrock-agentcore-lookalike/runtimes/x"),
            ]
        )

        assert results == []

    @mock_aws
    def test_agentcore_log_group_without_data_protection_status(self):
        """An AgentCore log group reporting no dataProtectionStatus must FAIL.

        dataProtectionStatus is modelled at the botocore pin, so its absence is not a parsing gap:
        it is the API reporting that the log group has never had a data protection policy, which
        means nothing is masked. Pins the resource identity too, since the finding has to name the
        log group an operator must remediate.
        """
        results = run_check([log_group(RUNTIME_LOG_GROUP)])

        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert (
            results[0].status_extended
            == f"AgentCore log group {RUNTIME_LOG_GROUP} does not have an active data protection policy, so sensitive data written by the agent is not masked."
        )
        assert results[0].resource_id == RUNTIME_LOG_GROUP
        assert (
            results[0].resource_arn
            == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:{RUNTIME_LOG_GROUP}:*"
        )
        assert results[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_agentcore_log_group_with_activated_policy(self):
        """ACTIVATED is the only dataProtectionStatus that must PASS: masking is running today."""
        results = run_check(
            [log_group(RUNTIME_LOG_GROUP, data_protection_status="ACTIVATED")]
        )

        assert len(results) == 1
        assert results[0].status == "PASS"
        assert (
            results[0].status_extended
            == f"AgentCore log group {RUNTIME_LOG_GROUP} has a data protection policy activated."
        )

    @mock_aws
    def test_agentcore_log_group_with_inactive_policy(self):
        """DELETED, ARCHIVED and DISABLED must each FAIL, not MANUAL.

        All three were read successfully, so nothing is unknown; they mean the same thing
        operationally, which is that nothing is being masked at ingestion today. Together with
        ACTIVATED these are all four values the enum carries at the botocore pin.
        """
        for status in ("DELETED", "ARCHIVED", "DISABLED"):
            results = run_check(
                [log_group(RUNTIME_LOG_GROUP, data_protection_status=status)]
            )

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert (
                results[0].status_extended
                == f"AgentCore log group {RUNTIME_LOG_GROUP} does not have an active data protection policy, so sensitive data written by the agent is not masked."
            )

    @mock_aws
    def test_agentcore_log_group_inheriting_account_policy(self):
        """A log group inheriting the account policy must PASS with no status of its own.

        An account-level policy surfaces as ACCOUNT_DATA_PROTECTION in inheritedProperties and
        leaves dataProtectionStatus absent, so a check reading only dataProtectionStatus would FAIL
        a log group that is fully masked. ACCOUNT_DATA_PROTECTION is the only value the
        InheritedProperty enum carries at the botocore pin.
        """
        results = run_check(
            [
                log_group(
                    VENDED_LOG_GROUP,
                    inherited_properties=["ACCOUNT_DATA_PROTECTION"],
                )
            ]
        )

        assert len(results) == 1
        assert results[0].status == "PASS"
        assert (
            results[0].status_extended
            == f"AgentCore log group {VENDED_LOG_GROUP} inherits the account-level data protection policy."
        )

    @mock_aws
    def test_agentcore_log_groups_mixed(self):
        """Multi-resource: one report per in-scope log group, with the PASS/FAIL split asserted.

        A loop that stopped at the first log group, or one that let the out-of-scope Lambda group
        through, would not produce exactly these two verdicts.
        """
        results = run_check(
            [
                log_group(RUNTIME_LOG_GROUP),
                log_group(VENDED_LOG_GROUP, data_protection_status="ACTIVATED"),
                log_group("/aws/lambda/unrelated-function"),
            ]
        )

        assert len(results) == 2
        assert {result.resource_id: result.status for result in results} == {
            RUNTIME_LOG_GROUP: "FAIL",
            VENDED_LOG_GROUP: "PASS",
        }

    @mock_aws
    def test_log_groups_not_retrieved_is_manual(self):
        """An unreadable inventory must yield one account-level MANUAL, not PASS and not FAIL.

        PASS would assert masking never observed; FAIL would invent a finding against log groups
        nothing is known about. The report is attributed to the account rather than to a log group,
        because no log group was read.
        """
        results = run_check(None)

        assert len(results) == 1
        assert results[0].status == "MANUAL"
        assert (
            results[0].status_extended
            == "Log groups could not be retrieved, so data protection policies for AgentCore log groups could not be verified."
        )
        assert results[0].resource_id == AWS_ACCOUNT_NUMBER
        assert results[0].region == AWS_REGION_US_EAST_1
        assert results[0].resource_tags == []

    @mock_aws
    def test_configured_prefix_brings_a_custom_log_group_into_scope(self):
        """A configured prefix must put a log group outside the AWS defaults in scope and FAIL it.

        AgentCore log delivery can be pointed at an arbitrarily named log group, so an operator who
        does that has no coverage until the prefix is configured.
        """
        results = run_check(
            [log_group("/company/agents/support-bot")],
            audit_config={
                "agentcore_log_group_name_prefixes": ["/company/agents/"],
            },
        )

        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].resource_id == "/company/agents/support-bot"

    @mock_aws
    def test_configured_prefix_replaces_the_defaults(self):
        """A configured prefix list REPLACES the defaults, so a real AgentCore group drops out.

        This is the sharp edge of the setting and the reason it is pinned: an operator who adds only
        their own prefix silences the check for /aws/bedrock-agentcore/ and
        /aws/vendedlogs/bedrock-agentcore/, with no finding to show it happened. They must list the
        defaults alongside their own.
        """
        results = run_check(
            [log_group(RUNTIME_LOG_GROUP)],
            audit_config={
                "agentcore_log_group_name_prefixes": ["/company/agents/"],
            },
        )

        assert results == []

    def test_shipped_config_matches_the_check_defaults(self):
        """The prefixes shipped in config.yaml must equal the check's in-code defaults.

        The same two prefixes are written twice, and the shipped config wins wherever it is used, so
        a prefix added only to the in-code list would be silently ignored by every operator running
        the default config -- and an unmatched log group produces no finding at all, not a FAIL. This
        makes that drift a failing test instead of missing coverage.

        The provider is mocked around the import because importing the check module constructs
        `logs_client`, which reads the global provider's identity. Every other test here reaches that
        import through `run_check`, which mocks it; this one imports the module directly for the
        constant, so without the patch it is the only test in the file that cannot be selected on its
        own -- 12 of 13 pass alone, and did not.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_agentcore_data_protection_policy_enabled.cloudwatch_log_group_agentcore_data_protection_policy_enabled import (
                DEFAULT_AGENTCORE_LOG_GROUP_PREFIXES,
            )

        repo_root = pathlib.Path(os.path.dirname(os.path.realpath(__file__))).parents[5]
        shipped = yaml.safe_load(
            (repo_root / "prowler" / "config" / "config.yaml").read_text()
        )

        assert (
            shipped["aws"]["agentcore_log_group_name_prefixes"]
            == DEFAULT_AGENTCORE_LOG_GROUP_PREFIXES
        )

    @mock_aws
    def test_explicit_null_prefixes_fall_back_to_the_defaults(self):
        """An explicitly null prefix list must fall back to the defaults, not silence the check.

        A bare `agentcore_log_group_name_prefixes:` in the YAML parses as None. Passing that
        straight to startswith would raise, and treating it as an empty list would skip every log
        group and report nothing.
        """
        results = run_check(
            [log_group(RUNTIME_LOG_GROUP)],
            audit_config={"agentcore_log_group_name_prefixes": None},
        )

        assert len(results) == 1
        assert results[0].status == "FAIL"

    @mock_aws
    def test_an_explicitly_empty_prefix_list_selects_no_log_group(self):
        """An empty list is a CONFIGURED value and must not fall back to the defaults.

        This is the only way an operator can say "no log group is in scope for this check", and the
        docstring promises a configured list REPLACES the defaults. Reading it with `or` treated `[]`
        as absent and re-imposed the defaults, so the check reported on a log group the operator had
        deliberately excluded, and no configuration could turn it off.

        It is the pair with the null case above that carries the assertion: null must fall back and
        empty must not, and a fix that collapsed both to one behaviour would satisfy either test
        alone. The distinction is only visible when both are present.
        """
        results = run_check(
            [log_group(RUNTIME_LOG_GROUP)],
            audit_config={"agentcore_log_group_name_prefixes": []},
        )

        assert results == []
