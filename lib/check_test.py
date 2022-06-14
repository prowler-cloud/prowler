import importlib


class Test_Check:
    def test_import_check(self):
        test_cases = [
            {
                "name": "Test valid check path",
                "input": "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials",
                "expected": "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials",
            }
        ]
        for test in test_cases:
            assert importlib.import_module(test["input"]).__name__ == test["expected"]
