import sure  # noqa

from prowler.providers.aws.lib.arn.arn import arn_parsing

ACCOUNT_ID = "123456789012"
RESOURCE_TYPE = "role"
IAM_ROLE = "test-role"


class Test_ARN_Parsing:
    def test_arn_parsing(self):
        test_cases = [
            {
                "input_arn": f"arn:aws:iam::{ACCOUNT_ID}:{RESOURCE_TYPE}/{IAM_ROLE}",
                "expected": {
                    "partition": "aws",
                    "service": "iam",
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE,
                    "resource": IAM_ROLE,
                },
            }
        ]
        for test in test_cases:
            input_arn = test["input_arn"]
            parsed_arn = arn_parsing(input_arn)
            parsed_arn.partition.should.equal(test["expected"]["partition"])
            parsed_arn.service.should.equal(test["expected"]["service"])
            parsed_arn.region.should.equal(test["expected"]["region"])
            parsed_arn.account_id.should.equal(test["expected"]["account_id"])
            parsed_arn.resource_type.should.equal(test["expected"]["resource_type"])
            parsed_arn.resource.should.equal(test["expected"]["resource"])
