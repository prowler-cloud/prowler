import pytest

from prowler.providers.aws.services.iam.lib.policy import (
    _get_patterns_from_standard_value,
    check_admin_access,
    check_full_service_access,
    get_effective_actions,
    has_codebuild_trusted_principal,
    has_public_principal,
    has_restrictive_source_arn_condition,
    is_codebuild_using_allowed_github_org,
    is_condition_block_restrictive,
    is_condition_block_restrictive_organization,
    is_condition_block_restrictive_sns_endpoint,
    is_condition_restricting_from_private_ip,
    is_policy_public,
)

TRUSTED_AWS_ACCOUNT_NUMBER = "123456789012"
NON_TRUSTED_AWS_ACCOUNT_NUMBER = "111222333444"
TRUSTED_AWS_ACCOUNT_NUMBER_LIST = ["123456789012", "123456789013", "123456789014"]

TRUSTED_ORGANIZATION_ID = "o-123456789012"
NON_TRUSTED_ORGANIZATION_ID = "o-111222333444"

ALL_ORGS = "*"


class Test_Policy:
    def test_get_patterns_from_standard_value_string(self):
        """Test _get_patterns_from_standard_value with a string input"""
        result = _get_patterns_from_standard_value("s3:GetObject")
        assert result == {"s3:GetObject"}

        result = _get_patterns_from_standard_value("")
        assert result == {""}

    def test_get_patterns_from_standard_value_list(self):
        """Test _get_patterns_from_standard_value with a list input"""
        result = _get_patterns_from_standard_value(["s3:GetObject", "s3:PutObject"])
        assert result == {"s3:GetObject", "s3:PutObject"}

        result = _get_patterns_from_standard_value([])
        assert result == set()

        result = _get_patterns_from_standard_value(["s3:GetObject", 123, None])
        assert result == {"s3:GetObject"}

    def test_get_patterns_from_standard_value_invalid_input(self):
        """Test _get_patterns_from_standard_value with invalid inputs"""
        result = _get_patterns_from_standard_value(None)
        assert result == set()

        result = _get_patterns_from_standard_value(123)
        assert result == set()

    def test_get_effective_actions_empty_policy(self):
        """Test get_effective_actions with an empty policy"""
        result = get_effective_actions({})
        assert result == set()

        result = get_effective_actions({"Version": "2012-10-17"})
        assert result == set()

    def test_get_effective_actions_simple_allow(self):
        """Test get_effective_actions with a simple Allow statement"""
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:GetObject"},
        }
        result = get_effective_actions(policy)
        assert result == {"s3:GetObject"}

    def test_get_effective_actions_simple_deny(self):
        """Test get_effective_actions with a simple Deny statement"""
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Deny", "Action": "s3:GetObject"},
        }
        result = get_effective_actions(policy)
        assert result == set()

    def test_get_effective_actions_allow_and_deny(self):
        """Test get_effective_actions with both Allow and Deny statements"""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]},
                {"Effect": "Deny", "Action": "s3:GetObject"},
            ],
        }
        result = get_effective_actions(policy)
        assert result == {"s3:PutObject"}

    def test_get_effective_actions_with_not_action(self):
        """Test get_effective_actions with NotAction statements"""
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "NotAction": "s3:GetObject"},
        }
        result = get_effective_actions(policy)
        assert "s3:GetObject" not in result
        assert "s3:PutObject" in result

    def test_get_effective_actions_with_wildcards(self):
        """Test get_effective_actions with wildcard actions"""
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:*"},
        }
        result = get_effective_actions(policy)
        assert "s3:GetObject" in result
        assert "s3:PutObject" in result
        assert "s3:ListBucket" in result

    def test_get_effective_actions_with_invalid_effect(self):
        """Test get_effective_actions with invalid Effect value"""
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Invalid", "Action": "s3:GetObject"},
        }
        result = get_effective_actions(policy)
        assert result == set()

    def test_get_effective_actions_with_multiple_statements(self):
        """Test get_effective_actions with multiple statements"""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]},
                {"Effect": "Allow", "Action": "s3:ListBucket"},
                {"Effect": "Deny", "Action": "s3:PutObject"},
            ],
        }
        result = get_effective_actions(policy)
        assert result == {"s3:GetObject", "s3:ListBucket"}
        assert "s3:PutObject" not in result

    # Test lowercase context key name --> aws
    def test_condition_parser_string_equals_aws_SourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"aws:SourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "aws:SourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"aws:SourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_list(self):
        condition_statement = {
            "StringLike": {"aws:SourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_str(self):
        condition_statement = {
            "StringLike": {"aws:SourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:SourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str(self):
        condition_statement = {
            "StringEquals": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceOwner": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_list(self):
        condition_statement = {
            "StringEquals": {"aws:SourceOwner": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "aws:SourceOwner": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list(self):
        condition_statement = {
            "StringLike": {"aws:SourceOwner": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceOwner": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str(self):
        condition_statement = {
            "StringLike": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:SourceOwner": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"s3:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "s3:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"s3:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"s3:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_list(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "aws:PrincipalAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_str(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceArn_str(self):
        condition_statement = {
            "StringEquals": {
                "aws:SourceArn": f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "aws:SourceArn": f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_list(self):
        condition_statement = {
            "StringLike": {"aws:PrincipalAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_str(self):
        condition_statement = {
            "StringLike": {"aws:PrincipalAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:PrincipalAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_list(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_str(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_list(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_str(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_list(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_str(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_list(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_str(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"aws:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "aws:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"aws:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_list(self):
        condition_statement = {
            "StringLike": {"aws:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_str(self):
        condition_statement = {
            "StringLike": {"aws:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    # Test uppercase context key name --> AWS
    def test_condition_parser_string_equals_AWS_SourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "AWS:SourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceAccount_list(self):
        condition_statement = {
            "StringLike": {"AWS:SourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceAccount_str(self):
        condition_statement = {
            "StringLike": {"AWS:SourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"AWS:SourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceOwner_str(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceOwner_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceOwner": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceOwner_list(self):
        condition_statement = {
            "StringEquals": {"AWS:SourceOwner": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "AWS:SourceOwner": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceOwner_list(self):
        condition_statement = {
            "StringLike": {"AWS:SourceOwner": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceOwner": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceOwner_str(self):
        condition_statement = {
            "StringLike": {"AWS:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceOwner_str_not_valid(self):
        condition_statement = {
            "StringLike": {"AWS:SourceOwner": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_S3_ResourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"S3:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_S3_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "S3:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_S3_ResourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"S3:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_S3_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"S3:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_PrincipalAccount_list(self):
        condition_statement = {
            "StringEquals": {"AWS:PrincipalAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "AWS:PrincipalAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_PrincipalAccount_str(self):
        condition_statement = {
            "StringEquals": {"AWS:PrincipalAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_PrincipalAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"AWS:PrincipalAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalAccount_list(self):
        condition_statement = {
            "StringLike": {"AWS:PrincipalAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:PrincipalAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalAccount_str(self):
        condition_statement = {
            "StringLike": {"AWS:PrincipalAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"AWS:PrincipalAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_SourceArn_list(self):
        condition_statement = {
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_SourceArn_str(self):
        condition_statement = {
            "ArnLike": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_PrincipalArn_list(self):
        condition_statement = {
            "ArnLike": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_PrincipalArn_str(self):
        condition_statement = {
            "ArnLike": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_AWS_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_SourceArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_SourceArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_PrincipalArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_PrincipalArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_AWS_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceArn_list(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceArn_str(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_SourceArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:SourceArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalArn_list(self):
        condition_statement = {
            "StringLike": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
                ]
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:PrincipalArn": [
                    f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                    f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test",
                ]
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalArn_str(self):
        condition_statement = {
            "StringLike": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:PrincipalArn": f"arn:aws:cloudtrail:eu-west-1:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/test"
            }
        }

        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_ResourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"AWS:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_ResourceAccount_str(self):
        condition_statement = {
            "StringEquals": {"AWS:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_AWS_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringEquals": {"AWS:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_ResourceAccount_list(self):
        condition_statement = {
            "StringLike": {"AWS:ResourceAccount": [TRUSTED_AWS_ACCOUNT_NUMBER]}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            }
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_ResourceAccount_str(self):
        condition_statement = {
            "StringLike": {"AWS:ResourceAccount": TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_AWS_ResourceAccount_str_not_valid(self):
        condition_statement = {
            "StringLike": {"AWS:ResourceAccount": NON_TRUSTED_AWS_ACCOUNT_NUMBER}
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_two_lists_unrestrictive(self):
        condition_statement = {
            "StringLike": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            },
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            },
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_two_lists_both_restrictive(self):
        condition_statement = {
            "StringLike": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            },
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            },
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_two_lists_first_restrictive(self):
        condition_statement = {
            "StringLike": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            },
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                    f"arn:aws:cloudtrail:*:{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            },
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_two_lists_second_restrictive(self):
        condition_statement = {
            "StringLike": {
                "AWS:ResourceAccount": [
                    TRUSTED_AWS_ACCOUNT_NUMBER,
                    NON_TRUSTED_AWS_ACCOUNT_NUMBER,
                ]
            },
            "ArnLike": {
                "AWS:SourceArn": [
                    f"arn:aws:cloudtrail:*:{TRUSTED_AWS_ACCOUNT_NUMBER}:trail/*",
                ]
            },
        }
        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_allowing_cross_account_with_invalid_block(self):
        condition_statement = {
            "StringLike": {
                "s3:prefix": [
                    "home/",
                ]
            },
        }
        assert not is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER, True
        )

    def test_condition_parser_string_equals_vpc(self):
        condition_statement = {"StringEquals": {"aws:SourceVpc": "vpc-123456"}}

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER, True
        )

    def test_condition_parser_string_equals_vpc_list(self):
        condition_statement = {"StringEquals": {"aws:sourcevpc": ["vpc-123456"]}}

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER, True
        )

    def test_condition_parser_string_equals_vpc_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceVpc": ["vpc-123456", "vpc-654321"]}
        }

        assert is_condition_block_restrictive(
            condition_statement, TRUSTED_AWS_ACCOUNT_NUMBER, True
        )

    def test_condition_parser_string_equals_aws_PrincipalOrgID_list(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalOrgID": [TRUSTED_ORGANIZATION_ID]}
        }
        assert is_condition_block_restrictive_organization(condition_statement)

    def test_condition_parser_string_equals_aws_PrincipalOrgID_list_multiple_items(
        self,
    ):
        condition_statement = {
            "StringEquals": {
                "aws:PrincipalOrgID": [
                    TRUSTED_ORGANIZATION_ID,
                    NON_TRUSTED_ORGANIZATION_ID,
                ]
            }
        }
        assert is_condition_block_restrictive_organization(condition_statement)

    def test_condition_parser_string_equals_aws_PrincipalOrgID_str(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalOrgID": TRUSTED_ORGANIZATION_ID}
        }
        assert is_condition_block_restrictive_organization(condition_statement)

    def test_condition_parser_string_equals_aws_All_Orgs_list_multiple_items(
        self,
    ):
        condition_statement = {
            "StringEquals": {
                "aws:PrincipalOrgID": [
                    TRUSTED_ORGANIZATION_ID,
                    ALL_ORGS,
                ]
            }
        }
        assert not is_condition_block_restrictive_organization(condition_statement)

    def test_condition_parser_string_equals_aws_All_Orgs_str(self):
        condition_statement = {"StringEquals": {"aws:PrincipalOrgID": ALL_ORGS}}
        assert not is_condition_block_restrictive_organization(condition_statement)

    @pytest.mark.parametrize(
        "condition_value,expected",
        [
            ("*@example.com", True),
            ("https://events.pagerduty.com/integration/<api-key>/enqueue", True),
            (
                "arn:aws:sns:eu-west-2:123456789012:example-topic:995be20c-a7e3-44ca-8c18-77cb263d15e7",
                True,
            ),
            ("*@*.com", False),
            ("*@*", False),
            ("*@example.*", False),
            ("https://events.pagerduty.com/integration/*/enqueue", False),
            ("arn:aws:sns:eu-west-2:123456789012:example-topic:*", False),
            (
                "arn:aws:sns:eu-west-2:*:example-topic:995be20c-a7e3-44ca-8c18-77cb263d15e7",
                False,
            ),
        ],
    )
    def test_condition_parser_string_equals_sns_endpoint_str(
        self, condition_value: str, expected: bool
    ):
        condition_statement = {"StringEquals": {"SNS:Endpoint": condition_value}}
        assert (
            is_condition_block_restrictive_sns_endpoint(condition_statement) == expected
        )

        condition_statement = {"StringLike": {"SNS:Endpoint": condition_value}}
        assert (
            is_condition_block_restrictive_sns_endpoint(condition_statement) == expected
        )

    def test_policy_allows_cross_account_access_with_root_and_wildcard_principal(self):
        policy_allow_root_and_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER}:root", "*"]
                    },
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_public(
            policy_allow_root_and_wildcard_principal,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            is_cross_account_allowed=False,
        )

    def test_policy_does_not_allow_cross_account_access_with_specific_root_principal(
        self,
    ):
        policy_allow_specific_root_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER}:root"]
                    },
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_public(
            policy_allow_specific_root_principal,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            is_cross_account_allowed=False,
        )

    def test_policy_does_not_allow_cross_account_access_with_deny_effect(self):
        policy_deny_specific_root_principal = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": [f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER}:root"]
                    },
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_public(
            policy_deny_specific_root_principal,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            is_cross_account_allowed=False,
        )

    def test_cross_account_access_trusted_account_list(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER_LIST[0]}:root"
                    },
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        assert not is_policy_public(
            policy,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            is_cross_account_allowed=False,
            trusted_account_ids=TRUSTED_AWS_ACCOUNT_NUMBER_LIST,
        )

    def test_cross_account_access_with_principal_list_trusted_account_list(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER_LIST[0]}:root",
                            f"arn:aws:iam::{NON_TRUSTED_AWS_ACCOUNT_NUMBER}:root",
                        ]
                    },
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(
            policy,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            is_cross_account_allowed=False,
            trusted_account_ids=TRUSTED_AWS_ACCOUNT_NUMBER_LIST,
        )

    def test_policy_allows_public_access_with_wildcard_principal(self):
        policy_allow_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_public(
            policy_allow_wildcard_principal,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            not_allowed_actions=["s3:*"],
        )

    def test_policy_allows_public_access_with_aws_wildcard_principal(self):
        policy_allow_aws_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_public(
            policy_allow_aws_wildcard_principal,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            not_allowed_actions=["s3:*"],
        )

    def test_policy_does_not_allow_public_access_with_specific_aws_principal(self):
        policy_allow_specific_aws_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER}:root"
                    },
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_public(
            policy_allow_specific_aws_principal, TRUSTED_AWS_ACCOUNT_NUMBER
        )

    def test_policy_does_not_allow_public_access_with_condition(self):
        policy_allow_aws_wildcard_principal_with_condition = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}},
                }
            ]
        }
        assert not is_policy_public(
            policy_allow_aws_wildcard_principal_with_condition,
            TRUSTED_AWS_ACCOUNT_NUMBER,
        )

    def test_policy_allows_full_service_access_with_wildcard_action_and_resource(self):
        policy_allow_wildcard_action_and_resource = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_wildcard_action_and_resource
        )

    def test_policy_allows_full_service_access_with_wildcard_action_and_resource_using_unicode(
        self,
    ):
        policy_allow_wildcard_action_and_resource = {
            "Statement": [
                {
                    "Effect": "\u0041llow",
                    "Action": "\u00733:*",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_wildcard_action_and_resource
        )

    def test_policy_allows_full_service_access_with_wildcard_action_and_resource_using_double_start(
        self,
    ):
        policy_allow_wildcard_action_and_resource = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:**",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_wildcard_action_and_resource
        )

    def test_policy_does_not_allow_full_service_access_with_specific_get_action(self):
        policy_allow_specific_get_action = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:Get*",
                    "Resource": "*",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_allow_specific_get_action)

    def test_policy_does_not_allow_full_service_access_with_bucket_wildcard_resource(
        self,
    ):
        policy_allow_bucket_wildcard_resource = {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::example_bucket/*",
            }
        }
        assert not check_full_service_access(
            "s3", policy_allow_bucket_wildcard_resource
        )

    def test_policy_does_not_allow_full_service_access_with_specific_bucket(self):
        policy_allow_specific_bucket = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_allow_specific_bucket)

    def test_policy_allows_full_service_access_with_not_action_excluding_other_service(
        self,
    ):
        policy_allow_not_action_excluding_other_service = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "ec2:*",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_not_action_excluding_other_service
        )

    def test_policy_allows_full_service_access_with_invalid_service_as_not_action(
        self,
    ):
        policy_allow_not_action_excluding_other_service = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "prowler:check",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_not_action_excluding_other_service
        )

    def test_policy_does_not_allow_full_service_access_with_not_action_including_service(
        self,
    ):
        policy_not_action_including_service = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:*",
                    "Resource": "*",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_not_action_including_service)

    def test_is_condition_restricting_from_private_ip_no_condition(self):
        assert not is_condition_restricting_from_private_ip({})

    def test_is_condition_restricting_from_private_ip(self):
        condition_from_private_ip = {
            "IpAddress": {"aws:SourceIp": "10.0.0.22"},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ip)

    def test_is_condition_restricting_from_public_ip(self):
        condition_not_from_private_ip = {
            "IpAddress": {"aws:SourceIp": "1.2.3.4"},
        }
        assert not is_condition_restricting_from_private_ip(
            condition_not_from_private_ip
        )

    def test_is_condition_restricting_from_private_ipv6(self):
        condition_from_private_ipv6 = {
            "IpAddress": {"aws:SourceIp": "fd00::1"},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ipv6)

    def test_is_condition_restricting_from_public_ipv6(self):
        condition_not_from_private_ipv6 = {
            "IpAddress": {"aws:SourceIp": "2001:0db8::1"},
        }
        assert is_condition_restricting_from_private_ip(condition_not_from_private_ipv6)

    def test_is_condition_restricting_from_private_ip_network(self):
        condition_from_private_ip_network = {
            "IpAddress": {"aws:SourceIp": "10.0.0.0/24"},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ip_network
        )

    def test_is_condition_restricting_from_public_ip_network(self):
        condition_from_public_ip_network = {
            "IpAddress": {"aws:SourceIp": "1.2.3.0/24"},
        }

        assert not is_condition_restricting_from_private_ip(
            condition_from_public_ip_network
        )

    def test_is_condition_restricting_from_private_ipv6_network(self):
        condition_from_private_ipv6_network = {
            "IpAddress": {"aws:SourceIp": "fd00::/8"},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ipv6_network
        )

    def test_is_condition_restricting_from_private_ip_array(self):
        condition_from_private_ip_array = {
            "IpAddress": {"aws:SourceIp": ["10.0.0.22", "192.168.1.1"]},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ip_array)

    def test_is_condition_restricting_from_private_ipv6_array(self):
        condition_from_private_ipv6_array = {
            "IpAddress": {"aws:SourceIp": ["fd00::1", "fe80::1"]},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ipv6_array
        )

    def test_is_condition_restricting_from_mixed_ip_array(self):
        condition_from_mixed_ip_array = {
            "IpAddress": {"aws:SourceIp": ["10.0.0.22", "2001:0db8::1"]},
        }
        assert is_condition_restricting_from_private_ip(condition_from_mixed_ip_array)

    def test_is_condition_restricting_from_mixed_ip_array_not_private(self):
        condition_from_mixed_ip_array_not_private = {
            "IpAddress": {"aws:SourceIp": ["1.2.3.4", "2001:0db8::1"]},
        }
        assert not is_condition_restricting_from_private_ip(
            condition_from_mixed_ip_array_not_private
        )

    def test_is_condition_restricting_from_private_ip_from_invalid_ip(self):
        condition_from_invalid_ip = {
            "IpAddress": {"aws:SourceIp": "256.256.256.256"},
        }
        assert not is_condition_restricting_from_private_ip(condition_from_invalid_ip)

    def test_is_policy_public_(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(
            policy,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            not_allowed_actions=["elasticfilesystem:ClientMount"],
        )

    def test_is_policy_public_with_principal_dict(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(
            policy,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            not_allowed_actions=["elasticfilesystem:ClientMount"],
        )

    def test_is_policy_public_with_secure_conditions_and_allowed_conditions(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                        "StringEquals": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER},
                    },
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_with_secure_conditions_and_allowed_conditions_nested(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                        "StringEquals": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER},
                        "StringEqualsIfExists": {
                            "aws:SourceVpce": "vpce-1234567890abcdef0"
                        },
                    },
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_with_secure_conditions_and_allowed_conditions_nested_dict(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                        "StringEquals": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER},
                        "StringEqualsIfExists": {
                            "aws:SourceVpce": {
                                "vpce-1234567890abcdef0": "vpce-1234567890abcdef0"
                            }
                        },
                    },
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_with_secure_conditions_and_allowed_conditions_nested_dict_key(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:ClientMount",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                        "StringEquals": {"aws:SourceOwner": TRUSTED_AWS_ACCOUNT_NUMBER},
                        "StringEqualsIfExists": {
                            "aws:SourceVpce": {
                                "vpce-1234567890abcdef0": "vpce-1234567890abcdef0"
                            }
                        },
                    },
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_with_action_wildcard(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "elasticfilesystem:*",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_allowing_all_actions(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_allowing_other_account(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{TRUSTED_AWS_ACCOUNT_NUMBER}:root"
                    },
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_secrets_manager(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "secretsmanager.amazonaws.com"},
                    "Action": "lambda:GetFunction",
                    "Resource": "*",
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_eks(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "lambda:GetFunction",
                    "Resource": "*",
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_cross_cross_service_confused_deputy(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": "*",
                }
            ]
        }
        assert is_policy_public(
            policy, TRUSTED_AWS_ACCOUNT_NUMBER, check_cross_service_confused_deputy=True
        )

    def test_is_policy_public_cross_cross_service_confused_deputy_ignored(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": "*",
                }
            ]
        }
        assert not is_policy_public(
            policy,
            TRUSTED_AWS_ACCOUNT_NUMBER,
            check_cross_service_confused_deputy=False,
        )

    def test_is_policy_public_alexa_condition(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "alexa-connectedhome.amazon.com"},
                    "Action": "lambda:GetFunction",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"lambda:EventSourceToken": "test"}},
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_private_org_s3_bucket(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Sid": "test",
                    "Effect": "Allow",
                    "Principal": {"Service": "personalize.amazonaws.com"},
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringLike": {"aws:SourceOrgID": "o-123456"}},
                }
            ]
        }
        assert not is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_is_policy_public_ip(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["*"],
                    "Condition": {"IpAddress": {"aws:SourceIp": ["0.0.0.0/0"]}},
                    "Resource": "*",
                }
            ],
        }
        assert is_policy_public(policy, TRUSTED_AWS_ACCOUNT_NUMBER)

    def test_check_admin_access(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
        }
        assert check_admin_access(policy)

    def test_check_admin_access_false(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
        }
        assert not check_admin_access(policy)

    def test_check_admin_access_not_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}],
        }
        assert check_admin_access(policy)

    def test_check_admin_access_not_action_with_random_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": "prowler:action", "Resource": "*"}
            ],
        }
        assert check_admin_access(policy)

    def test_check_admin_access_not_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "NotResource": "*"}],
        }
        assert not check_admin_access(policy)

    def test_check_admin_access_not_resource_with_random_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "NotResource": "prowler:resource"}
            ],
        }
        assert check_admin_access(policy)


def test_is_codebuild_using_allowed_github_org_allows():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is True
    assert org_name == "allowed-org"


def test_is_codebuild_using_allowed_github_org_denies():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/not-allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name == "not-allowed-org"


def test_is_codebuild_using_allowed_github_org_no_codebuild_principal():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name is None


def test_is_codebuild_using_allowed_github_org_invalid_url():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com//test"  # Malformed, no org
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is False
    assert org_name is None


def test_has_codebuild_trusted_principal_true():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert has_codebuild_trusted_principal(trust_policy) is True


def test_has_codebuild_trusted_principal_false():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert has_codebuild_trusted_principal(trust_policy) is False


def test_has_codebuild_trusted_principal_empty():
    trust_policy = {}
    assert has_codebuild_trusted_principal(trust_policy) is False


def test_is_codebuild_using_allowed_github_org_principal_string():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "codebuild.amazonaws.com",
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is True
    assert org_name == "allowed-org"


def test_is_codebuild_using_allowed_github_org_principal_list():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": ["codebuild.amazonaws.com", "lambda.amazonaws.com"],
                "Action": "sts:AssumeRole",
            }
        ],
    }
    github_repo_url = "https://github.com/allowed-org/repo"
    allowed_organizations = ["allowed-org"]
    is_allowed, org_name = is_codebuild_using_allowed_github_org(
        trust_policy, github_repo_url, allowed_organizations
    )
    assert is_allowed is True
    assert org_name == "allowed-org"


def test_has_codebuild_trusted_principal_string():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "codebuild.amazonaws.com",
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert has_codebuild_trusted_principal(trust_policy) is True


def test_has_codebuild_trusted_principal_list():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": ["codebuild.amazonaws.com", "lambda.amazonaws.com"],
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assert has_codebuild_trusted_principal(trust_policy) is True


class Test_has_public_principal:
    """Tests for the has_public_principal function"""

    def test_has_public_principal_wildcard_string(self):
        """Test public principal detection with wildcard string"""
        statement = {"Principal": "*"}
        assert has_public_principal(statement) is True

    def test_has_public_principal_root_arn_string(self):
        """Test public principal detection with root ARN string"""
        statement = {"Principal": "arn:aws:iam::*:root"}
        assert has_public_principal(statement) is True

    def test_has_public_principal_aws_dict_wildcard(self):
        """Test public principal detection with AWS dict containing wildcard"""
        statement = {"Principal": {"AWS": "*"}}
        assert has_public_principal(statement) is True

    def test_has_public_principal_aws_dict_root_arn(self):
        """Test public principal detection with AWS dict containing root ARN"""
        statement = {"Principal": {"AWS": "arn:aws:iam::*:root"}}
        assert has_public_principal(statement) is True

    def test_has_public_principal_aws_list_wildcard(self):
        """Test public principal detection with AWS list containing wildcard"""
        statement = {"Principal": {"AWS": ["arn:aws:iam::123456789012:user/test", "*"]}}
        assert has_public_principal(statement) is True

    def test_has_public_principal_aws_list_root_arn(self):
        """Test public principal detection with AWS list containing root ARN"""
        statement = {
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/test", "arn:aws:iam::*:root"]
            }
        }
        assert has_public_principal(statement) is True

    def test_has_public_principal_canonical_user_wildcard(self):
        """Test public principal detection with CanonicalUser wildcard"""
        statement = {"Principal": {"CanonicalUser": "*"}}
        assert has_public_principal(statement) is True

    def test_has_public_principal_canonical_user_root_arn(self):
        """Test public principal detection with CanonicalUser root ARN"""
        statement = {"Principal": {"CanonicalUser": "arn:aws:iam::*:root"}}
        assert has_public_principal(statement) is True

    def test_has_public_principal_no_principal(self):
        """Test with statement that has no Principal field"""
        statement = {"Effect": "Allow", "Action": "s3:GetObject"}
        assert has_public_principal(statement) is False

    def test_has_public_principal_empty_principal(self):
        """Test with empty principal"""
        statement = {"Principal": ""}
        assert has_public_principal(statement) is False

    def test_has_public_principal_specific_account(self):
        """Test with specific account principal (not public)"""
        statement = {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
        assert has_public_principal(statement) is False

    def test_has_public_principal_service_principal(self):
        """Test with service principal (not public)"""
        statement = {"Principal": {"Service": "lambda.amazonaws.com"}}
        assert has_public_principal(statement) is False

    def test_has_public_principal_mixed_principals(self):
        """Test with mixed principals including public one"""
        statement = {
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/test"],
                "Service": "lambda.amazonaws.com",
                "CanonicalUser": "*",
            }
        }
        assert has_public_principal(statement) is True


class Test_has_restrictive_source_arn_condition:
    """Tests for the has_restrictive_source_arn_condition function"""

    def test_no_condition_block(self):
        """Test statement without Condition block"""
        statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        assert has_restrictive_source_arn_condition(statement) is False

    def test_no_source_arn_condition(self):
        """Test with condition block but no aws:SourceArn"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_restrictive_source_arn_s3_bucket(self):
        """Test restrictive SourceArn condition with S3 bucket"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
        }
        assert has_restrictive_source_arn_condition(statement) is True

    def test_restrictive_source_arn_lambda_function(self):
        """Test restrictive SourceArn condition with Lambda function"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:MyFunction"
                }
            },
        }
        assert has_restrictive_source_arn_condition(statement) is True

    def test_non_restrictive_global_wildcard(self):
        """Test non-restrictive SourceArn with global wildcard"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": "*"}},
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_non_restrictive_service_wildcard(self):
        """Test non-restrictive SourceArn with service wildcard"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::*"}},
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_non_restrictive_multi_wildcard(self):
        """Test non-restrictive SourceArn with multiple wildcards"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:*:*:*:*"}},
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_non_restrictive_resource_wildcard(self):
        """Test non-restrictive SourceArn with resource wildcard"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:*"}
            },
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_source_arn_list_with_valid_arn(self):
        """Test SourceArn condition with list containing valid ARN"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket2"]
                }
            },
        }
        assert has_restrictive_source_arn_condition(statement) is True

    def test_source_arn_list_with_wildcard(self):
        """Test SourceArn condition with list containing wildcard"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": ["arn:aws:s3:::bucket1", "*"]}},
        }
        assert has_restrictive_source_arn_condition(statement) is False

    def test_source_arn_with_account_validation_match(self):
        """Test SourceArn with account validation - matching account"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:MyFunction"
                }
            },
        }
        assert has_restrictive_source_arn_condition(statement, "123456789012") is True

    def test_source_arn_with_account_validation_mismatch(self):
        """Test SourceArn with account validation - non-matching account"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:MyFunction"
                }
            },
        }
        assert has_restrictive_source_arn_condition(statement, "987654321098") is False

    def test_source_arn_with_account_wildcard(self):
        """Test SourceArn with account wildcard"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:lambda:us-east-1:*:function:MyFunction"
                }
            },
        }
        assert has_restrictive_source_arn_condition(statement, "123456789012") is False

    def test_source_arn_s3_bucket_no_account_field(self):
        """Test SourceArn with S3 bucket (no account field) - should be restrictive"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
        }
        assert has_restrictive_source_arn_condition(statement, "123456789012") is True

    def test_source_arn_case_insensitive(self):
        """Test SourceArn condition key is case insensitive"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::my-bucket"}},
        }
        assert has_restrictive_source_arn_condition(statement) is True

    def test_source_arn_mixed_operators(self):
        """Test SourceArn with multiple condition operators"""
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Condition": {
                "ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"},
                "StringEquals": {"aws:SourceAccount": "123456789012"},
            },
        }
        assert has_restrictive_source_arn_condition(statement) is True
