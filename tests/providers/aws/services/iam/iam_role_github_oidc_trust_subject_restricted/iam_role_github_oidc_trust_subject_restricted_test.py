from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.iam."
    "iam_role_github_oidc_trust_subject_restricted."
    "iam_role_github_oidc_trust_subject_restricted"
)
AWS_ACCOUNT_ID = "123456789012"
ROLE_NAME = "github-role"
GITHUB_PROVIDER = (
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
)
OTHER_PROVIDER = f"arn:aws:iam::{AWS_ACCOUNT_ID}:oidc-provider/accounts.google.com"
SUB_KEY = "token.actions.githubusercontent.com:sub"
PASS_MESSAGE = f"IAM Role {ROLE_NAME} restricts GitHub Actions OIDC trust to specific repository owners."
FAIL_MESSAGE = f"IAM Role {ROLE_NAME} does not restrict GitHub Actions OIDC trust to allowed repository owners."


def github_statement(condition=None, action="sts:AssumeRoleWithWebIdentity"):
    """Build a GitHub Actions OIDC trust statement."""
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": GITHUB_PROVIDER},
        "Action": action,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def run_check(trust_policy=None, audit_config=None):
    """Create an IAM role with Moto and run the check against the IAM service."""
    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1], audit_config=audit_config or {}
    )
    iam_api = client("iam")
    for url in (
        "https://token.actions.githubusercontent.com",
        "https://accounts.google.com",
    ):
        iam_api.create_open_id_connect_provider(
            Url=url,
            ClientIDList=["sts.amazonaws.com"],
            ThumbprintList=["a" * 40],
        )

    role_arn = None
    if trust_policy is not None:
        response = iam_api.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=dumps(trust_policy),
        )
        role_arn = response["Role"]["Arn"]

    from prowler.providers.aws.services.iam.iam_service import IAM

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
    ):
        from prowler.providers.aws.services.iam.iam_role_github_oidc_trust_subject_restricted.iam_role_github_oidc_trust_subject_restricted import (
            iam_role_github_oidc_trust_subject_restricted,
        )

        results = iam_role_github_oidc_trust_subject_restricted().execute()
    return results, role_arn


def assert_report(results, role_arn, status, status_extended):
    """Assert the check status and resource fields."""
    assert len(results) == 1
    report = results[0]
    assert report.status == status
    assert report.status_extended == status_extended
    assert report.resource_id == ROLE_NAME
    assert report.resource_arn == role_arn


@mock_aws
def test_no_resources():
    results, _ = run_check()
    assert results == []


@mock_aws
def test_non_github_oidc_role_is_out_of_scope():
    results, _ = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": OTHER_PROVIDER},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ],
        }
    )
    assert results == []


@mock_aws
def test_string_like_subject_passes():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:acme/infra:*"}})
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_repository_wildcard_passes_without_allowlist():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/*:*"}})],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_owner_only_subject_passes_without_allowlist():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/*"}})],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_owner_only_subject_passes_with_matching_allowlist():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/*"}})],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["acme"]},
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_owner_only_subject_fails_with_nonmatching_allowlist():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/*"}})],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["other"]},
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_empty_owner_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:/infra:*"}})],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_empty_repository_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/:*"}})],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_owner_allowlist_matching_is_case_insensitive():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement({"StringLike": {SUB_KEY: "repo:acme/*"}})],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["Acme"]},
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_any_specific_owner_passes_without_allowlist():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:other/infra:*"}})
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_string_equals_subject_passes():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"StringEquals": {SUB_KEY: "repo:acme/infra:ref:refs/heads/main"}}
                )
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_case_insensitive_action_and_subject_key_pass():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"StringLike": {SUB_KEY.upper(): "repo:acme/infra:*"}},
                    action="STS:ASSUMEROLEWITHWEBIDENTITY",
                )
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_wildcard_action_passes_with_restricted_subject():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"StringLike": {SUB_KEY: "repo:acme/infra:*"}},
                    action="STS:*",
                )
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_partial_action_wildcard_with_missing_subject_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [github_statement(action="sts:AssumeRoleWithWebIdentit?")],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_partial_action_wildcard_with_unrestricted_owner_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"StringLike": {SUB_KEY: "repo:*/infra:*"}},
                    action="sts:AssumeRole*",
                )
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_subject_value_prefix_remains_case_sensitive():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "Repo:acme/infra:*"}})
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_for_all_values_string_like_subject_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"ForAllValues:StringLike": {SUB_KEY: "repo:acme/infra:*"}}
                )
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_for_all_values_string_equals_subject_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"ForAllValues:StringEquals": {SUB_KEY: "repo:acme/infra:ref:main"}}
                )
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_for_any_value_string_like_subject_passes():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {"ForAnyValue:StringLike": {SUB_KEY: "repo:acme/infra:*"}}
                )
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_allowed_repository_owner_passes():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:acme/infra:*"}})
            ],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["acme"]},
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_repository_owner_outside_allowlist_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:other/infra:*"}})
            ],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["acme"]},
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_all_subject_owners_must_be_allowed():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {
                        "StringLike": {
                            SUB_KEY: [
                                "repo:acme/infra:*",
                                "repo:other/service:*",
                            ]
                        }
                    }
                )
            ],
        },
        audit_config={"iam_github_oidc_allowed_owners": ["acme"]},
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_positive_subject_with_not_equals_exclusion_passes():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement(
                    {
                        "StringLike": {SUB_KEY: "repo:acme/infra:*"},
                        "StringNotEquals": {
                            SUB_KEY: "repo:acme/infra:ref:refs/heads/dev"
                        },
                    }
                )
            ],
        }
    )
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


@mock_aws
def test_missing_subject_fails():
    results, role_arn = run_check(
        {"Version": "2012-10-17", "Statement": [github_statement()]}
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_wildcard_owner_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:*/infra:*"}})
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_if_exists_subject_condition_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLikeIfExists": {SUB_KEY: "repo:acme/infra:*"}})
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)


@mock_aws
def test_one_unrestricted_github_statement_fails():
    results, role_arn = run_check(
        {
            "Version": "2012-10-17",
            "Statement": [
                github_statement({"StringLike": {SUB_KEY: "repo:acme/infra:*"}}),
                github_statement(),
            ],
        }
    )
    assert_report(results, role_arn, "FAIL", FAIL_MESSAGE)
