import yaml
from mock import MagicMock

from prowler.providers.aws.lib.mutelist.mutelist import MutelistAWS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_SOUTH_3,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
)


class TestMutelistAWS:
    def test_get_mutelist_file_from_local_file(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"
        mutelist = MutelistAWS(mutelist_path=mutelist_path)

        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = MutelistAWS(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}

    def test_validate_mutelist(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"

        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist = MutelistAWS(mutelist_content=mutelist_fixture)

        assert mutelist.validate_mutelist()
        assert mutelist.mutelist == mutelist_fixture

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = MutelistAWS(mutelist_content=mutelist_fixture)

        assert not mutelist.validate_mutelist()
        assert mutelist.mutelist == mutelist_fixture

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)
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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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

    def test_is_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = AWS_REGION_US_EAST_1

        assert MutelistAWS.is_item_matched(muted_regions, finding_region)

    def test_is_muted_in_region_wildcard(self):
        muted_regions = ["*"]
        finding_region = AWS_REGION_US_EAST_1

        assert MutelistAWS.is_item_matched(muted_regions, finding_region)

    def test_is_not_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = "eu-west-2"

        assert not MutelistAWS.is_item_matched(muted_regions, finding_region)

    def test_is_muted_in_check(self):
        muted_checks = {
            "check_test": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }
        mutelist = MutelistAWS(mutelist_content={})

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

        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

        assert mutelist.is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_tags(self):
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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

        assert mutelist.is_muted(
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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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
        mutelist = MutelistAWS(mutelist_content=mutelist_content)

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

        assert MutelistAWS.is_item_matched(mutelist_tags, "environment=dev")

        assert MutelistAWS.is_item_matched(
            mutelist_tags,
            "environment=dev | project=prowler",
        )

        assert not (
            MutelistAWS.is_item_matched(
                mutelist_tags,
                "environment=pro",
            )
        )

    def test_is_muted_in_tags_regex(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]
        assert MutelistAWS.is_item_matched(
            mutelist_tags,
            "environment=test | proj=prowler",
        )

        assert MutelistAWS.is_item_matched(
            mutelist_tags,
            "env=prod | project=prowler",
        )

        assert not MutelistAWS.is_item_matched(
            mutelist_tags,
            "environment=prod | project=myproj",
        )

    def test_is_muted_in_tags_with_no_tags_in_finding(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]
        finding_tags = ""
        assert not MutelistAWS.is_item_matched(mutelist_tags, finding_tags)

    def test_is_excepted(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": ["eu-central-1", "eu-south-3"],
            "Resources": ["test"],
            "Tags": ["environment=test", "project=.*"],
        }
        mutelist = MutelistAWS(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-central-1",
            "test",
            "environment=test",
        )

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-3",
            "test",
            "environment=test",
        )

        assert mutelist.is_excepted(
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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

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
            "Tags": ["environment=test"],
        }
        mutelist = MutelistAWS(mutelist_content={})

        assert mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

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
        mutelist = MutelistAWS(mutelist_content={})

        assert not mutelist.is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-2",
            "test",
            "environment=test",
        )

    def test_is_muted_in_resource(self):
        mutelist_resources = ["prowler", "^test", "prowler-pro"]

        assert MutelistAWS.is_item_matched(mutelist_resources, "prowler")
        assert MutelistAWS.is_item_matched(mutelist_resources, "prowler-test")
        assert MutelistAWS.is_item_matched(mutelist_resources, "test-prowler")
        assert not MutelistAWS.is_item_matched(mutelist_resources, "random")

    def test_is_muted_in_resource_starting_by_star(self):
        allowlist_resources = ["*.es"]

        assert MutelistAWS.is_item_matched(allowlist_resources, "google.es")
