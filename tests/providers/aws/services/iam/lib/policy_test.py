from prowler.providers.aws.services.iam.lib.policy import (
    check_admin_access,
    check_full_service_access,
    is_condition_block_restrictive,
    is_condition_block_restrictive_organization,
    is_condition_restricting_from_private_ip,
    is_policy_public,
)

TRUSTED_AWS_ACCOUNT_NUMBER = "123456789012"
NON_TRUSTED_AWS_ACCOUNT_NUMBER = "111222333444"

TRUSTED_ORGANIZATION_ID = "o-123456789012"
NON_TRUSTED_ORGANIZATION_ID = "o-111222333444"

ALL_ORGS = "*"


class Test_Policy:
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
