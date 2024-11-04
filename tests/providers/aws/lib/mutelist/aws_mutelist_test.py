import io
from json import dumps
from os import path

import botocore
import yaml
from boto3 import client, resource
from mock import MagicMock, patch
from moto import mock_aws

from prowler.config.config import encoding_format_utf_8
from prowler.providers.aws.lib.mutelist.mutelist import AWSMutelist
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.services.awslambda.awslambda_service_test import (
    create_zip_file,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_SOUTH_3,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

MUTELIST_FIXTURE_PATH = "tests/providers/aws/lib/mutelist/fixtures/aws_mutelist.yaml"


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "Invoke":
        return {
            "Payload": io.BytesIO(
                dumps(
                    {
                        "Mutelist": {
                            "Accounts": {
                                "*": {
                                    "Checks": {
                                        "*": {
                                            "Regions": ["*"],
                                            "Resources": ["*"],
                                            "Tags": ["key:value"],
                                        },
                                    }
                                },
                            }
                        }
                    }
                ).encode(encoding_format_utf_8)
            )
        }

    return make_api_call(self, operation_name, kwarg)


class TestAWSMutelist:
    @mock_aws
    def test_get_mutelist_file_from_s3(self):
        aws_provider = set_mocked_aws_provider()
        # Create bucket and upload mutelist yaml
        s3_resource = resource("s3", region_name=AWS_REGION_US_EAST_1)
        s3_resource.create_bucket(Bucket="test-mutelist")
        s3_resource.Object("test-mutelist", "mutelist.yaml").put(
            Body=open(
                MUTELIST_FIXTURE_PATH,
                "rb",
            )
        )

        with open(MUTELIST_FIXTURE_PATH) as f:
            fixture_mutelist = yaml.safe_load(f)["Mutelist"]
        mutelist_path = "s3://test-mutelist/mutelist.yaml"
        mutelist = AWSMutelist(
            mutelist_path=mutelist_path, session=aws_provider.session.current_session
        )

        assert mutelist.mutelist == fixture_mutelist
        assert mutelist.mutelist_file_path == mutelist_path

    @mock_aws
    def test_get_mutelist_file_from_s3_not_present(self):
        aws_provider = set_mocked_aws_provider()
        mutelist_path = "s3://test-mutelist/mutelist.yaml"

        mutelist = AWSMutelist(
            mutelist_path=mutelist_path, session=aws_provider.session.current_session
        )
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    @mock_aws
    def test_get_mutelist_file_from_dynamodb(self):
        aws_provider = set_mocked_aws_provider()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table_name = "test-mutelist"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
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
        dynamo_db_mutelist = {
            "Accounts": "*",
            "Checks": "iam_user_hardware_mfa_enabled",
            "Regions": [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            "Resources": ["keyword"],
            "Exceptions": {},
        }
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "iam_user_hardware_mfa_enabled": {
                            "Regions": [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                            "Resources": ["keyword"],
                            "Exceptions": {},
                        },
                    }
                },
            }
        }
        table.put_item(Item=dynamo_db_mutelist)

        mutelist = AWSMutelist(
            mutelist_path=table_arn,
            session=aws_provider.session.current_session,
            aws_account_id=aws_provider.identity.account,
        )
        assert mutelist.mutelist == mutelist_content
        assert mutelist.mutelist_file_path == table_arn

    @mock_aws
    def test_get_mutelist_file_from_dynamodb_with_tags(self):
        aws_provider = set_mocked_aws_provider()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table_name = "test-mutelist"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
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
        dynamo_db_mutelist = {
            "Accounts": "*",
            "Checks": "*",
            "Regions": ["*"],
            "Resources": ["*"],
            "Tags": ["environment=dev"],
        }
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["environment=dev"],
                        },
                    }
                },
            }
        }
        table.put_item(Item=dynamo_db_mutelist)

        mutelist = AWSMutelist(
            mutelist_path=table_arn,
            session=aws_provider.session.current_session,
            aws_account_id=aws_provider.identity.account,
        )
        assert mutelist.mutelist == mutelist_content
        assert mutelist.mutelist_file_path == table_arn

    @mock_aws
    def test_get_mutelist_file_from_dynamodb_not_present(self):
        aws_provider = set_mocked_aws_provider()
        table_name = "non-existent"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
        mutelist = AWSMutelist(
            mutelist_path=table_arn,
            session=aws_provider.session.current_session,
            aws_account_id=aws_provider.identity.account,
        )
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == table_arn

    @mock_aws(config={"lambda": {"use_docker": False}})
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_get_mutelist_file_from_lambda(self):
        aws_provider = set_mocked_aws_provider()
        lambda_name = "mutelist"
        lambda_role = "lambda_role"
        lambda_client = client("lambda", region_name=AWS_REGION_US_EAST_1)
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        lambda_role_assume_policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        lambda_role_arn = iam_client.create_role(
            RoleName=lambda_role,
            AssumeRolePolicyDocument=dumps(lambda_role_assume_policy),
        )["Role"]["Arn"]
        lambda_code = """def handler(event, context):
  checks = {}
  checks["*"] = { "Regions": [ "*" ], "Resources": [ "" ], Optional("Tags"): [ "key:value" ] }

  al = { "Mutelist": { "Accounts": { "*": { "Checks": checks } } } }
  return al"""

        lambda_function = lambda_client.create_function(
            FunctionName=lambda_name,
            Runtime="3.9",
            Role=lambda_role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": create_zip_file(code=lambda_code).read()},
            Description="test lambda function",
        )
        lambda_function_arn = lambda_function["FunctionArn"]
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["key:value"],
                        },
                    }
                },
            }
        }

        mutelist = AWSMutelist(
            mutelist_path=lambda_function_arn,
            session=aws_provider.session.current_session,
            aws_account_id=aws_provider.identity.account,
        )
        assert mutelist.mutelist == mutelist_content
        assert mutelist.mutelist_file_path == lambda_function_arn

    @mock_aws
    def test_get_mutelist_file_from_lambda_invalid_arn(self):
        aws_provider = set_mocked_aws_provider()
        lambda_function_arn = "invalid_arn"

        mutelist = AWSMutelist(
            mutelist_path=lambda_function_arn,
            session=aws_provider.session.current_session,
            aws_account_id=aws_provider.identity.account,
        )
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == lambda_function_arn

    def test_get_mutelist_file_from_local_file(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        mutelist = AWSMutelist(mutelist_path=mutelist_path)

        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = AWSMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}

    def test_validate_mutelist(self):
        mutelist_path = MUTELIST_FIXTURE_PATH

        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist = AWSMutelist(mutelist_content=mutelist_fixture)

        assert mutelist.validate_mutelist()
        assert mutelist.mutelist == mutelist_fixture

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = AWSMutelist(mutelist_content=mutelist_fixture)

        assert not mutelist.validate_mutelist()
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_mutelist_findings_only_wildcard(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["prowler", "^test", "prowler-pro"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        # Finding
        finding_1 = MagicMock
        finding_1.check_metadata = MagicMock
        finding_1.check_metadata.CheckID = "check_test"
        finding_1.status = "FAIL"
        finding_1.region = AWS_REGION_US_EAST_1
        finding_1.resource_id = "prowler"
        finding_1.resource_tags = []

        assert mutelist.is_finding_muted(finding_1, AWS_ACCOUNT_NUMBER)

    def test_mutelist_all_exceptions_empty(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Tags": ["*"],
                            "Regions": [AWS_REGION_US_EAST_1],
                            "Resources": ["*"],
                            "Exceptions": {
                                "Tags": [],
                                "Regions": [],
                                "Accounts": [],
                                "Resources": [],
                            },
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        # Check Findings
        finding_1 = MagicMock
        finding_1.check_metadata = MagicMock
        finding_1.check_metadata.CheckID = "check_test"
        finding_1.status = "FAIL"
        finding_1.region = AWS_REGION_US_EAST_1
        finding_1.resource_id = "prowler"
        finding_1.resource_tags = []

        assert mutelist.is_finding_muted(finding_1, AWS_ACCOUNT_NUMBER)

    def test_is_muted_with_everything_excepted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "athena_*": {
                            "Regions": "*",
                            "Resources": "*",
                            "Tags": "*",
                            "Exceptions": {
                                "Accounts": ["*"],
                                "Regions": ["*"],
                                "Resources": ["*"],
                                "Tags": ["*"],
                            },
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_with_default_mutelist(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Tags": ["*"],
                            "Regions": ["*"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_with_default_mutelist_with_tags(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["Compliance=allow"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "Compliance=allow",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "Compliance=deny",
        )

    def test_is_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["prowler", "^test", "prowler-pro"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)
        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-pro-test",
            "",
        )

        assert not (
            mutelist.is_muted(AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", "")
        )

    def test_is_muted_wildcard(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": [".*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            mutelist.is_muted(AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", "")
        )

    def test_is_muted_asterisk(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            mutelist.is_muted(AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", "")
        )

    def test_is_muted_exceptions_before_match(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "accessanalyzer_enabled": {
                            "Exceptions": {
                                "Accounts": [],
                                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                                "Resources": [],
                                "Tags": [],
                            },
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["*"],
                        },
                        "sns_*": {
                            "Regions": ["*"],
                            "Resources": ["aws-controltower-*"],
                        },
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "sns_topics_not_publicly_accessible",
            AWS_REGION_EU_WEST_1,
            "aws-controltower-AggregateSecurityNotifications",
            "",
        )

    def test_is_muted_all_and_single_account(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test_2": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                        }
                    }
                },
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1],
                            "Resources": ["*"],
                        }
                    }
                },
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_2",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            mutelist.is_muted(AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", "")
        )

    def test_is_muted_all_and_single_account_with_different_resources(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test_1": {
                            "Regions": ["*"],
                            "Resources": ["resource_1", "resource_2"],
                        },
                    }
                },
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test_1": {
                            "Regions": ["*"],
                            "Resources": ["resource_3"],
                        }
                    }
                },
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_1",
            "",
        )

        assert mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

        assert not mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

    def test_is_muted_all_and_single_account_with_different_resources_and_exceptions(
        self,
    ):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test_1": {
                            "Regions": ["*"],
                            "Resources": ["resource_1", "resource_2"],
                            "Exceptions": {"Regions": [AWS_REGION_US_EAST_1]},
                        },
                    }
                },
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test_1": {
                            "Regions": ["*"],
                            "Resources": ["resource_3"],
                            "Exceptions": {"Regions": [AWS_REGION_EU_WEST_1]},
                        }
                    }
                },
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

        assert not mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_1",
            "",
        )

        assert mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_EU_WEST_1,
            "resource_2",
            "",
        )

        assert not mutelist.is_muted(
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_EU_WEST_1,
            "resource_3",
            "",
        )

    def test_is_muted_aws_default_mutelist(
        self,
    ):

        mutelist = AWSMutelist(
            mutelist_path=f"{path.dirname(path.realpath(__file__))}/../../../../../prowler/config/aws_mutelist.yaml"
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-BASELINE-CONFIG-AAAAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerGuardrailAWS-GR-AUDIT-BUCKET-PUBLIC-READ-PROHIBITED-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerGuardrailAWS-GR-DETECT",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "CLOUDTRAIL-ENABLED-ON-SHARED-ACCOUNTS-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-BASELINE-SERVICE-LINKED-ROLE-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-BASELINE-ROLES-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-SECURITY-TOPICS-AAAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-BASELINE-SERVICE-ROLES-AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerSecurityResources-AAAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerGuardrailAWS-GR-AUDIT-BUCKET-PUBLIC-WRITE-PROHIBITED-AAAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "AFT-Backend/AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "AWSControlTowerBP-BASELINE-CONFIG-MASTER/AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "AWSControlTowerBP-BASELINE-CLOUDTRAIL-MASTER/AAA",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "cloudformation_stacks_termination_protection_enabled",
            AWS_REGION_EU_WEST_1,
            "StackSet-AWSControlTowerBP-VPC-ACCOUNT-FACTORY-V1-AAA",
            "",
        )

    def test_is_muted_single_account(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1],
                            "Resources": ["prowler"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert not (
            mutelist.is_muted(AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", "")
        )

    def test_is_muted_search(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["prowler"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "resource-prowler",
            "",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-resource",
            "",
        )

    def test_is_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = AWS_REGION_US_EAST_1

        assert AWSMutelist.is_item_matched(muted_regions, finding_region)

    def test_is_muted_in_region_wildcard(self):
        muted_regions = ["*"]
        finding_region = AWS_REGION_US_EAST_1

        assert AWSMutelist.is_item_matched(muted_regions, finding_region)

    def test_is_not_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = "eu-west-2"

        assert not AWSMutelist.is_item_matched(muted_regions, finding_region)

    def test_is_muted_in_check(self):
        muted_checks = {
            "check_test": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            mutelist.is_muted_in_check(
                muted_checks,
                AWS_ACCOUNT_NUMBER,
                "check_test",
                "us-east-2",
                "test",
                "",
            )
        )

    def test_is_muted_in_check_regex(self):
        # Mutelist example
        muted_checks = {
            "s3_*": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }

        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_public_access",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_no_mfa_delete",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_policy_public_write_access",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            mutelist.is_muted_in_check(
                muted_checks,
                AWS_ACCOUNT_NUMBER,
                "iam_user_hardware_mfa_enabled",
                AWS_REGION_US_EAST_1,
                "test",
                "",
            )
        )

    def test_is_muted_lambda_generic_check(self):
        muted_checks = {
            "lambda_*": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_code",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_not_publicly_accessible",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_cors_policy",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_public",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_using_supported_runtimes",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_lambda_concrete_check(self):
        muted_checks = {
            "lambda_function_no_secrets_in_variables": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_tags_example1(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["environment=dev", "project=.*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "environment=dev",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not (
            mutelist.is_muted(
                AWS_ACCOUNT_NUMBER,
                "check_test",
                "us-east-2",
                "test",
                "environment=pro",
            )
        )

    def test_is_muted_tags_example2(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["environment=dev", "project=test(?!\.)"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "environment=dev | project=test",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "environment=dev",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=test.",
        )

    def test_is_muted_tags_and_logic(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["environment=dev", "project=prowler"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=myproj",
        )

    def test_is_muted_tags_or_logic_example1(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["environment=dev|project=.*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "project=prowler",
        )

    def test_is_muted_tags_or_logic_example2(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["project=(test|stage)"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "project=test",
        )

    def test_is_muted_tags_and_or_logic(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": ["team=dev", "environment=dev|project=.*"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "team=dev | environment=dev",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "team=dev | project=prowler",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "team=ops",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev",
        )

        assert not mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "project=myproj",
        )

    def test_is_muted_specific_account_with_other_account_excepted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_EU_WEST_1],
                            "Resources": ["*"],
                            "Tags": [],
                            "Exceptions": {"Accounts": ["111122223333"]},
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

        assert not mutelist.is_muted(
            "111122223333",
            "check_test",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

    def test_is_muted_complex_mutelist(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "s3_bucket_object_versioning": {
                            "Regions": [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                            "Resources": ["ci-logs", "logs", ".+-logs"],
                        },
                        "ecs_task_definitions_no_environment_secrets": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Exceptions": {
                                "Accounts": [AWS_ACCOUNT_NUMBER],
                                "Regions": [
                                    AWS_REGION_EU_WEST_1,
                                    AWS_REGION_EU_SOUTH_3,
                                ],
                            },
                        },
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["environment=dev"],
                        },
                    }
                },
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Exceptions": {
                                "Resources": ["test"],
                                "Tags": ["environment=prod"],
                            },
                        }
                    }
                },
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "test_check",
            AWS_REGION_EU_WEST_1,
            "prowler-logs",
            "environment=dev",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "ecs_task_definitions_no_environment_secrets",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

        assert mutelist.is_muted(
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_object_versioning",
            AWS_REGION_EU_WEST_1,
            "prowler-logs",
            "environment=dev",
        )

    def test_is_muted_in_tags(self):
        mutelist_tags = ["environment=dev", "project=prowler"]

        assert AWSMutelist.is_item_matched(mutelist_tags, "environment=dev")

        assert AWSMutelist.is_item_matched(
            mutelist_tags, "environment=dev | project=prowler"
        )

        assert AWSMutelist.is_item_matched(
            mutelist_tags, "environment=pro | project=prowler"
        )

        assert not (AWSMutelist.is_item_matched(mutelist_tags, "environment=pro"))

    def test_is_muted_in_tags_with_piped_tags(self):
        mutelist_tags = ["environment=dev|project=prowler"]

        assert AWSMutelist.is_item_matched(mutelist_tags, "environment=dev")

        assert AWSMutelist.is_item_matched(
            mutelist_tags, "environment=dev | project=prowler"
        )

        assert AWSMutelist.is_item_matched(
            mutelist_tags, "environment=pro | project=prowler"
        )

        assert not (AWSMutelist.is_item_matched(mutelist_tags, "environment=pro"))

    def test_is_muted_in_tags_regex(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]
        assert AWSMutelist.is_item_matched(
            mutelist_tags, "environment=test | proj=prowler"
        )

        assert AWSMutelist.is_item_matched(mutelist_tags, "env=prod | project=prowler")

        assert not AWSMutelist.is_item_matched(
            mutelist_tags, "environment=prod | project=myproj"
        )

    def test_is_muted_in_tags_with_no_tags_in_finding(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]
        finding_tags = ""
        assert not AWSMutelist.is_item_matched(mutelist_tags, finding_tags)

    def test_is_excepted(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": ["eu-central-1", "eu-south-3"],
            "Resources": ["test"],
            "Tags": ["environment=test", "project=.*"],
        }
        mutelist = AWSMutelist(mutelist_content={})
        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-central-1",
            "test",
            "environment=test",
        )

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test",
            "environment=test",
        )

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test123",
            "environment=test",
        )

    def test_is_excepted_only_in_account(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": [],
            "Resources": [],
            "Tags": [],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-central-1",
            "test",
            "environment=test",
        )

    def test_is_excepted_only_in_region(self):
        exceptions = {
            "Accounts": [],
            "Regions": [AWS_REGION_EU_CENTRAL_1, AWS_REGION_EU_SOUTH_3],
            "Resources": [],
            "Tags": [],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "test",
            "environment=test",
        )

    def test_is_excepted_only_in_resources(self):
        exceptions = {
            "Accounts": [],
            "Regions": [],
            "Resources": ["resource_1"],
            "Tags": [],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
        )

    def test_is_excepted_only_in_tags(self):
        exceptions = {
            "Accounts": [],
            "Regions": [],
            "Resources": [],
            "Tags": ["environment=test"],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
        )

    def test_is_excepted_in_account_and_tags(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": [],
            "Resources": [],
            "Tags": ["environment=test", "project=example"],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test | project=example",
        )

        assert not mutelist.is_excepted(
            exceptions,
            "111122223333",
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
        )

        assert not mutelist.is_excepted(
            exceptions,
            "111122223333",
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=dev",
        )

    def test_is_excepted_all_wildcard(self):
        exceptions = {
            "Accounts": ["*"],
            "Regions": ["*"],
            "Resources": ["*"],
            "Tags": ["*"],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions, AWS_ACCOUNT_NUMBER, "eu-south-2", "test", "environment=test"
        )
        assert not mutelist.is_excepted(
            exceptions, AWS_ACCOUNT_NUMBER, "eu-south-2", "test", None
        )

    def test_is_not_excepted(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": ["eu-central-1", "eu-south-3"],
            "Resources": ["test"],
            "Tags": ["environment=test", "project=.*"],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-2",
            "test",
            "environment=test",
        )

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "prowler",
            "environment=test",
        )

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test",
            "environment=pro",
        )

    def test_is_excepted_all_empty(self):
        exceptions = {
            "Accounts": [],
            "Regions": [],
            "Resources": [],
            "Tags": [],
        }
        mutelist = AWSMutelist(mutelist_content={})

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-2",
            "test",
            "environment=test",
        )

    def test_is_muted_in_resource(self):
        mutelist_resources = ["prowler", "^test", "prowler-pro"]

        assert AWSMutelist.is_item_matched(mutelist_resources, "prowler")
        assert AWSMutelist.is_item_matched(mutelist_resources, "prowler-test")
        assert AWSMutelist.is_item_matched(mutelist_resources, "test-prowler")
        assert not AWSMutelist.is_item_matched(mutelist_resources, "random")

    def test_is_muted_in_resource_starting_by_star(self):
        allowlist_resources = ["*.es"]

        assert AWSMutelist.is_item_matched(allowlist_resources, "google.es")

    def test_mute_finding(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                AWS_ACCOUNT_NUMBER: {
                    "Checks": {
                        "check_test": {
                            "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                            "Resources": ["prowler", "^test", "prowler-pro"],
                        }
                    }
                }
            }
        }
        mutelist = AWSMutelist(mutelist_content=mutelist_content)

        # Finding
        finding_1 = generate_finding_output(
            check_id="check_test",
            status="FAIL",
            region=AWS_REGION_US_EAST_1,
            resource_uid="prowler",
            resource_tags=[],
            muted=False,
        )

        muted_finding = mutelist.mute_finding(finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted
        assert muted_finding.raw["status"] == "FAIL"
