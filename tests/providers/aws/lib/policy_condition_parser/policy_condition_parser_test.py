from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_account_only_allowed_in_condition,
)

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_policy_condition_parser:
    def test_condition_parser_string_equals_aws_SourceAccount_list(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_str(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceAccount_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_list(self):
        condition_statement = {"StringLike": {"aws:SourceAccount": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_str(self):
        condition_statement = {"StringLike": {"aws:SourceAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:SourceAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str_not_valid(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )
        
    def test_condition_parser_string_equals_aws_SourceOwner_list(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceOwner": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:SourceOwner": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str_not_valid(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_list(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceOwner": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_SourceOwner_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:SourceOwner": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_list_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:SourceOwner": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceOwner_str_not_valid(self):
        condition_statement = {"StringLike": {"aws:SourceOwner": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )
    
    def test_condition_parser_string_equals_s3_ResourceAccount_list(self):
        condition_statement = {"StringEquals": {"s3:ResourceAccount": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_str(self):
        condition_statement = {"StringEquals": {"s3:ResourceAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"s3:ResourceAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_s3_ResourceAccount_str_not_valid(self):
        condition_statement = {"StringEquals": {"s3:ResourceAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_list(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalAccount": ["123456789012"]}
        }
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_str(self):
        condition_statement = {"StringEquals": {"aws:PrincipalAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:PrincipalAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_PrincipalAccount_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:PrincipalAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_list(self):
        condition_statement = {"StringLike": {"aws:PrincipalAccount": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_str(self):
        condition_statement = {"StringLike": {"aws:PrincipalAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:PrincipalAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalAccount_str_not_valid(self):
        condition_statement = {"StringLike": {"aws:PrincipalAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_list(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": ["arn:aws:cloudtrail:*:123456789012:trail/*"]}
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:*:123456789012:trail/*",
                    "arn:aws:cloudtrail:*:111222333444:trail/*",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_str(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": "arn:aws:cloudtrail:*:123456789012:trail/*"}
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": "arn:aws:cloudtrail:*:111222333444:trail/*"}
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_list(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": ["arn:aws:cloudtrail:*:123456789012:trail/*"]
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:PrincipalArn": [
                    "arn:aws:cloudtrail:*:123456789012:trail/*",
                    "arn:aws:cloudtrail:*:111222333444:trail/*",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_str(self):
        condition_statement = {
            "ArnLike": {"aws:PrincipalArn": "arn:aws:cloudtrail:*:123456789012:trail/*"}
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_like_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnLike": {"aws:PrincipalArn": "arn:aws:cloudtrail:*:111222333444:trail/*"}
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
                ]
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test",
                    "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test"
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_list(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
                ]
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test",
                    "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_str(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_arn_equals_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:PrincipalArn": "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test"
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_list(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
                ]
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test",
                    "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_str(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_SourceArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test"
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_list(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
                ]
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_list_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test",
                    "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test",
                ]
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_str(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
            }
        }

        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_PrincipalArn_str_not_valid(self):
        condition_statement = {
            "StringLike": {
                "aws:PrincipalArn": "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test"
            }
        }

        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_list(self):
        condition_statement = {
            "StringEquals": {"aws:ResourceAccount": ["123456789012"]}
        }
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_str(self):
        condition_statement = {"StringEquals": {"aws:ResourceAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:ResourceAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_equals_aws_ResourceAccount_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:ResourceAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_list(self):
        condition_statement = {"StringLike": {"aws:ResourceAccount": ["123456789012"]}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_str(self):
        condition_statement = {"StringLike": {"aws:ResourceAccount": "123456789012"}}
        assert is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_list_not_valid(self):
        condition_statement = {
            "StringLike": {"aws:ResourceAccount": ["123456789012", "111222333444"]}
        }
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )

    def test_condition_parser_string_like_aws_ResourceAccount_str_not_valid(self):
        condition_statement = {"StringLike": {"aws:ResourceAccount": "111222333444"}}
        assert not is_account_only_allowed_in_condition(
            condition_statement, AWS_ACCOUNT_NUMBER
        )
