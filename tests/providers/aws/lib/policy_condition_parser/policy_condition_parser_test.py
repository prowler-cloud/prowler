from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_condition_block_restrictive,
    is_condition_block_restrictive_organization,
)

TRUSTED_AWS_ACCOUNT_NUMBER = "123456789012"
NON_TRUSTED_AWS_ACCOUNT_NUMBER = "111222333444"

TRUSTED_ORGANIZATION_ID = "o-123456789012"
NON_TRUSTED_ORGANIZATION_ID = "o-111222333444"

ALL_ORGS = "*"


class Test_policy_condition_parser:
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
