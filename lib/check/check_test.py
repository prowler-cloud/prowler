import os

from lib.check.check import parse_checks_from_file


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

    def test_parse_checks_from_file(checks_file):
        test_cases = [
            {
                "name": "Test valid check path",
                "input": f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/checklistA.txt",
                "expected": {"check12", "check11", "extra72", "check13"},
            },
            {
                "name": "Test valid check path",
                "input": f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/checklistB.txt",
                "expected": {
                    "extra72",
                    "check13",
                    "check11",
                    "check12",
                    "check56",
                    "check2423",
                },
            },
        ]
        for test in test_cases:
            assert parse_checks_from_file(test["input"]) == test["expected"]
