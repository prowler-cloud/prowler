from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    condition_parser,
)

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_policy_condition_parser:
    def test_condition_parser_string_equals_list(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": ["123456789012"]}}
        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_string_equals_str(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": "123456789012"}}
        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_string_equals_list_not_valid(self):
        condition_statement = {
            "StringEquals": {"aws:SourceAccount": ["123456789012", "111222333444"]}
        }
        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_string_equals_str_not_valid(self):
        condition_statement = {"StringEquals": {"aws:SourceAccount": "111222333444"}}
        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnlike_list(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": ["arn:aws:cloudtrail:*:123456789012:trail/*"]}
        }

        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnlike_list_not_valid(self):
        condition_statement = {
            "ArnLike": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:*:123456789012:trail/*",
                    "arn:aws:cloudtrail:*:111222333444:trail/*",
                ]
            }
        }

        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnlike_str(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": "arn:aws:cloudtrail:*:123456789012:trail/*"}
        }

        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnlike_str_not_valid(self):
        condition_statement = {
            "ArnLike": {"aws:SourceArn": "arn:aws:cloudtrail:*:111222333444:trail/*"}
        }

        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnequals_list(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
                ]
            }
        }

        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnequals_list_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": [
                    "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test",
                    "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test",
                ]
            }
        }

        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnequals_str(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/test"
            }
        }

        assert condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)

    def test_condition_parser_arnequals_str_not_valid(self):
        condition_statement = {
            "ArnEquals": {
                "aws:SourceArn": "arn:aws:cloudtrail:eu-west-1:111222333444:trail/test"
            }
        }

        assert not condition_parser(condition_statement, AWS_ACCOUNT_NUMBER)
