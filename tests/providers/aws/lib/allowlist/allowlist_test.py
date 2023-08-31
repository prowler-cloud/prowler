import yaml
from boto3 import resource, session
from moto import mock_dynamodb, mock_s3

from prowler.providers.aws.lib.allowlist.allowlist import (
    is_allowlisted,
    is_allowlisted_in_check,
    is_allowlisted_in_region,
    is_allowlisted_in_tags,
    is_excepted,
    parse_allowlist_file,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_Allowlist:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test S3 allowlist
    @mock_s3
    def test_s3_allowlist(self):
        audit_info = self.set_mocked_audit_info()
        # Create bucket and upload allowlist yaml
        s3_resource = resource("s3", region_name=AWS_REGION)
        s3_resource.create_bucket(Bucket="test-allowlist")
        s3_resource.Object("test-allowlist", "allowlist.yaml").put(
            Body=open(
                "tests/providers/aws/lib/allowlist/fixtures/allowlist.yaml",
                "rb",
            )
        )

        with open("tests/providers/aws/lib/allowlist/fixtures/allowlist.yaml") as f:
            assert yaml.safe_load(f)["Allowlist"] == parse_allowlist_file(
                audit_info, "s3://test-allowlist/allowlist.yaml"
            )

    # Test DynamoDB allowlist
    @mock_dynamodb
    def test_dynamo_allowlist(self):
        audit_info = self.set_mocked_audit_info()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION)
        table_name = "test-allowlist"
        params = {
            "TableName": table_name,
            "KeySchema": [
                {"AttributeName": "Accounts", "KeyType": "HASH"},
                {"AttributeName": "Checks", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "Accounts", "AttributeType": "S"},
                {"AttributeName": "Checks", "AttributeType": "S"},
            ],
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
        table = dynamodb_resource.create_table(**params)
        table.put_item(
            Item={
                "Accounts": "*",
                "Checks": "iam_user_hardware_mfa_enabled",
                "Regions": ["eu-west-1", AWS_REGION],
                "Resources": ["keyword"],
            }
        )

        assert (
            "keyword"
            in parse_allowlist_file(
                audit_info,
                "arn:aws:dynamodb:"
                + AWS_REGION
                + ":"
                + str(AWS_ACCOUNT_NUMBER)
                + ":table/"
                + table_name,
            )["Accounts"]["*"]["Checks"]["iam_user_hardware_mfa_enabled"]["Resources"]
        )

    @mock_dynamodb
    def test_dynamo_allowlist_with_tags(self):
        audit_info = self.set_mocked_audit_info()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION)
        table_name = "test-allowlist"
        params = {
            "TableName": table_name,
            "KeySchema": [
                {"AttributeName": "Accounts", "KeyType": "HASH"},
                {"AttributeName": "Checks", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "Accounts", "AttributeType": "S"},
                {"AttributeName": "Checks", "AttributeType": "S"},
            ],
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
        table = dynamodb_resource.create_table(**params)
        table.put_item(
            Item={
                "Accounts": "*",
                "Checks": "*",
                "Regions": ["*"],
                "Resources": ["*"],
                "Tags": ["environment=dev"],
            }
        )

        assert (
            "environment=dev"
            in parse_allowlist_file(
                audit_info,
                "arn:aws:dynamodb:"
                + AWS_REGION
                + ":"
                + str(AWS_ACCOUNT_NUMBER)
                + ":table/"
                + table_name,
            )["Accounts"]["*"]["Checks"]["*"]["Tags"]
        )

    # Allowlist checks
    def test_is_allowlisted(self):
        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION, "eu-west-1"],
                            "Resources": ["prowler", "^test", "prowler-pro"],
                        }
                    }
                }
            }
        }

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler-test", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "test-prowler", ""
        )

        assert is_allowlisted(
            allowlist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "prowler-pro-test",
            "",
        )

        assert not (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_allowlisted_wildcard(self):
        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION, "eu-west-1"],
                            "Resources": [".*"],
                        }
                    }
                }
            }
        }

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler-test", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "test-prowler", ""
        )

        assert not (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_allowlisted_asterisk(self):
        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION, "eu-west-1"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler-test", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "test-prowler", ""
        )

        assert not (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_allowlisted_all_and_single_account(self):
        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test_2": {
                            "Regions": [AWS_REGION, "eu-west-1"],
                            "Resources": ["*"],
                        }
                    }
                },
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION],
                            "Resources": ["*"],
                        }
                    }
                },
            }
        }

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test_2", AWS_REGION, "prowler", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler-test", ""
        )

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "test-prowler", ""
        )

        assert not (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_allowlisted_single_account(self):
        allowlist = {
            "Accounts": {
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION],
                            "Resources": ["prowler"],
                        }
                    }
                }
            }
        }

        assert is_allowlisted(
            allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler", ""
        )

        assert not (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_allowlisted_in_region(self):
        # Allowlist example
        allowlisted_regions = [AWS_REGION, "eu-west-1"]
        allowlisted_resources = ["*"]

        assert is_allowlisted_in_region(
            allowlisted_regions, allowlisted_resources, None, AWS_REGION, "prowler", ""
        )

        assert is_allowlisted_in_region(
            allowlisted_regions,
            allowlisted_resources,
            None,
            AWS_REGION,
            "prowler-test",
            "",
        )

        assert is_allowlisted_in_region(
            allowlisted_regions,
            allowlisted_resources,
            None,
            AWS_REGION,
            "test-prowler",
            "",
        )

        assert not (
            is_allowlisted_in_region(
                allowlisted_regions,
                allowlisted_resources,
                None,
                "us-east-2",
                "test",
                "",
            )
        )

    def test_is_allowlisted_in_check(self):
        allowlisted_checks = {
            "check_test": {
                "Regions": [AWS_REGION, "eu-west-1"],
                "Resources": ["*"],
            }
        }

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "prowler-test",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "test-prowler",
            "",
        )

        assert not (
            is_allowlisted_in_check(
                allowlisted_checks,
                AWS_ACCOUNT_NUMBER,
                AWS_ACCOUNT_NUMBER,
                "check_test",
                "us-east-2",
                "test",
                "",
            )
        )

    def test_is_allowlisted_in_check_regex(self):
        # Allowlist example
        allowlisted_checks = {
            "s3_*": {
                "Regions": [AWS_REGION, "eu-west-1"],
                "Resources": ["*"],
            }
        }

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_public_access",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_no_mfa_delete",
            AWS_REGION,
            "prowler-test",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_policy_public_write_access",
            AWS_REGION,
            "test-prowler",
            "",
        )

        assert not (
            is_allowlisted_in_check(
                allowlisted_checks,
                AWS_ACCOUNT_NUMBER,
                AWS_ACCOUNT_NUMBER,
                "iam_user_hardware_mfa_enabled",
                AWS_REGION,
                "test",
                "",
            )
        )

    def test_is_allowlisted_lambda_generic_check(self):
        allowlisted_checks = {
            "lambda_*": {
                "Regions": [AWS_REGION, "eu-west-1"],
                "Resources": ["*"],
            }
        }

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_code",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_not_publicly_accessible",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_cors_policy",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_public",
            AWS_REGION,
            "prowler",
            "",
        )

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_using_supported_runtimes",
            AWS_REGION,
            "prowler",
            "",
        )

    def test_is_allowlisted_lambda_concrete_check(self):
        allowlisted_checks = {
            "lambda_function_no_secrets_in_variables": {
                "Regions": [AWS_REGION, "eu-west-1"],
                "Resources": ["*"],
            }
        }

        assert is_allowlisted_in_check(
            allowlisted_checks,
            AWS_ACCOUNT_NUMBER,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION,
            "prowler",
            "",
        )

    def test_is_allowlisted_tags(self):
        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION, "eu-west-1"],
                            "Resources": ["*"],
                            "Tags": ["environment=dev", "project=.*"],
                        }
                    }
                }
            }
        }

        assert is_allowlisted(
            allowlist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "prowler",
            "environment=dev",
        )

        assert is_allowlisted(
            allowlist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not (
            is_allowlisted(
                allowlist,
                AWS_ACCOUNT_NUMBER,
                "check_test",
                "us-east-2",
                "test",
                "environment=pro",
            )
        )

    def test_is_allowlisted_in_tags(self):
        allowlist_tags = ["environment=dev", "project=prowler"]
        allowlist_resource = "*"

        assert is_allowlisted_in_tags(
            allowlist_tags,
            "*",
            "prowler",
            "environment=dev",
        )

        assert is_allowlisted_in_tags(
            allowlist_tags,
            allowlist_resource,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not (
            is_allowlisted_in_tags(
                allowlist_tags,
                allowlist_resource,
                "test",
                "environment=pro",
            )
        )

    def test_is_allowlisted_in_tags_regex(self):
        allowlist_tags = ["environment=(dev|test)", ".*=prowler"]
        allowlist_resource = "*"

        assert is_allowlisted_in_tags(
            allowlist_tags,
            allowlist_resource,
            "prowler-test",
            "environment=test | proj=prowler",
        )

        assert is_allowlisted_in_tags(
            allowlist_tags,
            allowlist_resource,
            "prowler-test",
            "env=prod | project=prowler",
        )

        assert not is_allowlisted_in_tags(
            allowlist_tags,
            allowlist_resource,
            "prowler-test",
            "environment=prod | project=myproj",
        )

    def test_is_excepted(self):
        # Allowlist example
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": ["eu-central-1", "eu-south-3"],
            "Resources": ["test"],
            "Tags": ["environment=test", "project=.*"],
        }

        assert is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-central-1",
            "test",
            "environment=test",
        )

        assert is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test",
            "environment=test",
        )

        assert is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test123",
            "environment=test",
        )

        assert not is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-2",
            "test",
            "environment=test",
        )

        assert not is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "prowler",
            "environment=test",
        )

        assert not is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test",
            "environment=pro",
        )
