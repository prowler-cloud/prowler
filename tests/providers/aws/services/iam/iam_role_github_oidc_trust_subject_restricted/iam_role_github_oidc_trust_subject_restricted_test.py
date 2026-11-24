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
FAIL_MESSAGE = f"IAM Role {ROLE_NAME} allows GitHub Actions OIDC trust without a strictly restricted repository owner in the sub claim."


def github_statement(condition=None):
    """Build a GitHub Actions OIDC trust statement."""
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": GITHUB_PROVIDER},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def run_check(trust_policy=None):
    """Create an IAM role with Moto and run the check against the IAM service."""
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
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
def test_for_all_values_string_like_subject_passes():
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
    assert_report(results, role_arn, "PASS", PASS_MESSAGE)


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
