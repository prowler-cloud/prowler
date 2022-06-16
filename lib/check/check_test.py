import os

from lib.check.check import (
    exclude_checks_to_run,
    parse_checks_from_file,
    parse_groups_from_file,
)


class Test_Check:
    # def test_import_check(self):
    #     test_cases = [
    #         {
    #             "name": "Test valid check path",
    #             "input": "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials",
    #             "expected": "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials",
    #         }
    #     ]
    #     for test in test_cases:
    #         assert importlib.import_module(test["input"]).__name__ == test["expected"]

    def test_parse_checks_from_file(self):
        test_cases = [
            {
                "input": {
                    "path": f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/checklistA.json",
                    "provider": "aws",
                },
                "expected": {"check11", "check12", "check7777"},
            }
        ]
        for test in test_cases:
            check_file = test["input"]["path"]
            provider = test["input"]["provider"]
            assert parse_checks_from_file(check_file, provider) == test["expected"]

    def test_parse_groups_from_file(self):
        test_cases = [
            {
                "input": {"groups": ["gdpr"], "provider": "aws"},
                "expected": {"check11", "check12"},
            }
        ]
        for test in test_cases:
            provider = test["input"]["provider"]
            groups = test["input"]["groups"]
            assert parse_groups_from_file(groups, provider) == test["expected"]

    def test_exclude_checks_to_run(self):
        test_cases = [
            {
                "input": {
                    "check_list": {"check12", "check11", "extra72", "check13"},
                    "excluded_checks": {"check12", "check13"},
                },
                "expected": {"check11", "extra72"},
            },
            {
                "input": {
                    "check_list": {"check112", "check11", "extra72", "check13"},
                    "excluded_checks": {"check12", "check13", "check14"},
                },
                "expected": {"check112", "check11", "extra72"},
            },
        ]
        for test in test_cases:
            check_list = test["input"]["check_list"]
            excluded_checks = test["input"]["excluded_checks"]
            assert (
                exclude_checks_to_run(check_list, excluded_checks) == test["expected"]
            )
