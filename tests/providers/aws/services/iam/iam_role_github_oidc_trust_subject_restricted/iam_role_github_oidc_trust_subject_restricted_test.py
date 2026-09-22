from types import SimpleNamespace
from unittest import mock

from prowler.providers.aws.services.iam.iam_role_github_oidc_trust_subject_restricted.iam_role_github_oidc_trust_subject_restricted import (
    iam_role_github_oidc_trust_subject_restricted,
)

CHECK_MODULE = (
    "prowler.providers.aws.services.iam."
    "iam_role_github_oidc_trust_subject_restricted."
    "iam_role_github_oidc_trust_subject_restricted"
)


def role(policy):
    return SimpleNamespace(
        name="github-role",
        arn="arn:aws:iam::123456789012:role/github-role",
        assume_role_policy=policy,
    )


def github_statement(condition=None):
    statement = {
        "Effect": "Allow",
        "Principal": {
            "Federated": "arn:aws:iam::123456789012:oidc-provider/"
            "token.actions.githubusercontent.com"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def run_check(roles):
    iam = SimpleNamespace(roles=roles, region="us-east-1")
    with mock.patch(f"{CHECK_MODULE}.iam_client", new=iam):
        return iam_role_github_oidc_trust_subject_restricted().execute()


def test_valid_repository_owner_passes():
    results = run_check(
        [
            role(
                {
                    "Statement": [
                        github_statement(
                            {
                                "StringLike": {
                                    "token.actions.githubusercontent.com:sub": "repo:acme/infra:*"
                                }
                            }
                        )
                    ]
                }
            )
        ]
    )
    assert len(results) == 1
    assert results[0].status == "PASS"


def test_missing_condition_fails():
    results = run_check([role({"Statement": [github_statement()]})])
    assert len(results) == 1
    assert results[0].status == "FAIL"


def test_audience_only_condition_fails():
    results = run_check(
        [
            role(
                {
                    "Statement": [
                        github_statement(
                            {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                                }
                            }
                        )
                    ]
                }
            )
        ]
    )
    assert results[0].status == "FAIL"


def test_wildcard_repository_owner_fails():
    results = run_check(
        [
            role(
                {
                    "Statement": [
                        github_statement(
                            {
                                "StringLike": {
                                    "token.actions.githubusercontent.com:sub": "repo:acme*/infra:*"
                                }
                            }
                        )
                    ]
                }
            )
        ]
    )
    assert results[0].status == "FAIL"


def test_non_github_role_is_out_of_scope():
    results = run_check(
        [
            role(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                }
            )
        ]
    )
    assert results == []


def test_if_exists_subject_condition_fails():
    results = run_check(
        [
            role(
                {
                    "Statement": [
                        github_statement(
                            {
                                "StringLikeIfExists": {
                                    "token.actions.githubusercontent.com:sub": "repo:acme/infra:*"
                                }
                            }
                        )
                    ]
                }
            )
        ]
    )
    assert results[0].status == "FAIL"
