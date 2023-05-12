import sure  # noqa
from pytest import raises

from prowler.providers.aws.lib.arn.arn import iam_credentials_arn_parsing, is_valid_arn
from prowler.providers.aws.lib.arn.error import (
    RoleArnParsingEmptyResource,
    RoleArnParsingFailedMissingFields,
    RoleArnParsingIAMRegionNotEmpty,
    RoleArnParsingInvalidAccountID,
    RoleArnParsingInvalidResourceType,
    RoleArnParsingPartitionEmpty,
    RoleArnParsingServiceNotIAMnorSTS,
)

ACCOUNT_ID = "123456789012"
RESOURCE_TYPE_ROLE = "role"
RESOUCE_TYPE_USER = "user"
IAM_ROLE = "test-role"
IAM_SERVICE = "iam"
COMMERCIAL_PARTITION = "aws"
CHINA_PARTITION = "aws-cn"
GOVCLOUD_PARTITION = "aws-us-gov"


class Test_ARN_Parsing:
    def test_iam_credentials_arn_parsing(self):
        test_cases = [
            {
                "input_arn": f"arn:aws:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": COMMERCIAL_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:aws:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": COMMERCIAL_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{CHINA_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": CHINA_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{CHINA_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": CHINA_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{GOVCLOUD_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": GOVCLOUD_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{GOVCLOUD_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": GOVCLOUD_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
        ]
        for test in test_cases:
            input_arn = test["input_arn"]
            parsed_arn = iam_credentials_arn_parsing(input_arn)
            parsed_arn.partition.should.equal(test["expected"]["partition"])
            parsed_arn.service.should.equal(test["expected"]["service"])
            parsed_arn.region.should.equal(test["expected"]["region"])
            parsed_arn.account_id.should.equal(test["expected"]["account_id"])
            parsed_arn.resource_type.should.equal(test["expected"]["resource_type"])
            parsed_arn.resource.should.equal(test["expected"]["resource"])

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingFailedMissingFields(
        self,
    ):
        input_arn = ""
        with raises(RoleArnParsingFailedMissingFields) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingFailedMissingFields

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingIAMRegionNotEmpty(self):
        input_arn = "arn:aws:iam:eu-west-1:111111111111:user/prowler"
        with raises(RoleArnParsingIAMRegionNotEmpty) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingIAMRegionNotEmpty

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingPartitionEmpty(self):
        input_arn = "arn::iam::111111111111:user/prowler"
        with raises(RoleArnParsingPartitionEmpty) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingPartitionEmpty

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingServiceNotIAM(self):
        input_arn = "arn:aws:s3::111111111111:user/prowler"
        with raises(RoleArnParsingServiceNotIAMnorSTS) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingServiceNotIAMnorSTS

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingInvalidAccountID(self):
        input_arn = "arn:aws:iam::AWS_ACCOUNT_ID:user/prowler"
        with raises(RoleArnParsingInvalidAccountID) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingInvalidAccountID

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingInvalidResourceType(
        self,
    ):
        input_arn = "arn:aws:iam::111111111111:account/prowler"
        with raises(RoleArnParsingInvalidResourceType) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingInvalidResourceType

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingEmptyResource(self):
        input_arn = "arn:aws:iam::111111111111:role/"
        with raises(RoleArnParsingEmptyResource) as error:
            iam_credentials_arn_parsing(input_arn)

        assert error._excinfo[0] == RoleArnParsingEmptyResource

    def test_is_valid_arn(self):
        assert is_valid_arn("arn:aws:iam::012345678910:user/test")
        assert is_valid_arn("arn:aws-cn:ec2:us-east-1:123456789012:vpc/vpc-12345678")
        assert is_valid_arn("arn:aws-us-gov:s3:::bucket")
        assert not is_valid_arn("arn:azure:::012345678910:user/test")
        assert not is_valid_arn("arn:aws:iam::account:user/test")
        assert not is_valid_arn("arn:aws:::012345678910:resource")
