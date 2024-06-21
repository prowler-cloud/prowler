import yaml
from mock import MagicMock

from prowler.lib.mutelist.mutelist import (
    get_mutelist_file_from_local_file,
    is_excepted,
    is_muted,
    is_muted_in_check,
    is_muted_in_region,
    is_muted_in_resource,
    is_muted_in_tags,
    mutelist_findings,
    validate_mutelist,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_SOUTH_3,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class TestMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert get_mutelist_file_from_local_file(mutelist_path) == mutelist_fixture

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"

        assert get_mutelist_file_from_local_file(mutelist_path) == {}

    def test_validate_mutelist(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert validate_mutelist(mutelist_fixture) == mutelist_fixture

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = "tests/lib/mutelist/fixtures/aws_mutelist.yaml"
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]
        assert validate_mutelist(mutelist_fixture) == {}

    def test_mutelist_findings_only_wildcard(self):

        mutelist = {
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

        # Check Findings
        check_findings = []
        finding_1 = MagicMock
        finding_1.check_metadata = MagicMock
        finding_1.check_metadata.CheckID = "check_test"
        finding_1.status = "FAIL"
        finding_1.region = AWS_REGION_US_EAST_1
        finding_1.resource_id = "prowler"
        finding_1.resource_tags = []
        aws_provider = set_mocked_aws_provider()
        aws_provider._mutelist = mutelist

        check_findings.append(finding_1)

        muted_findings = mutelist_findings(aws_provider, check_findings)
        assert len(muted_findings) == 1
        assert muted_findings[0].status == "FAIL"
        assert muted_findings[0].muted

    def test_mutelist_all_exceptions_empty(self):

        mutelist = {
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

        # Check Findings
        check_findings = []
        finding_1 = MagicMock
        finding_1.check_metadata = MagicMock
        finding_1.check_metadata.CheckID = "check_test"
        finding_1.status = "FAIL"
        finding_1.region = AWS_REGION_US_EAST_1
        finding_1.resource_id = "prowler"
        finding_1.resource_tags = []
        aws_provider = set_mocked_aws_provider()
        aws_provider._mutelist = mutelist

        check_findings.append(finding_1)

        muted_findings = mutelist_findings(aws_provider, check_findings)
        assert len(muted_findings) == 1
        assert muted_findings[0].status == "FAIL"
        assert muted_findings[0].muted

    def test_is_muted_with_everything_excepted(self):
        mutelist = {
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

        assert not is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_with_default_mutelist(self):
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_with_default_mutelist_with_tags(self):
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "Compliance=allow",
        )

        assert not is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "athena_1",
            AWS_REGION_US_EAST_1,
            "prowler",
            "Compliance=deny",
        )

    def test_is_muted(self):

        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-pro-test",
            "",
        )

        assert not (
            is_muted(
                mutelist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_muted_wildcard(self):
        # Mutelist example
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            is_muted(
                mutelist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_muted_asterisk(self):
        # Mutelist example
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            is_muted(
                mutelist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_muted_exceptions_before_match(self):
        # Mutelist example
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "sns_topics_not_publicly_accessible",
            AWS_REGION_EU_WEST_1,
            "aws-controltower-AggregateSecurityNotifications",
            "",
        )

    def test_is_muted_all_and_single_account(self):
        # Mutelist example
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_2",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            is_muted(
                mutelist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_muted_all_and_single_account_with_different_resources(self):

        mutelist = {
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

        assert is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_1",
            "",
        )

        assert is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

        assert not is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

    def test_is_muted_all_and_single_account_with_different_resources_and_exceptions(
        self,
    ):

        mutelist = {
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

        assert not is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_2",
            "",
        )

        assert not is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_1",
            "",
        )

        assert is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_EU_WEST_1,
            "resource_2",
            "",
        )

        assert not is_muted(
            mutelist,
            "111122223333",
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_US_EAST_1,
            "resource_3",
            "",
        )

        assert not is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test_1",
            AWS_REGION_EU_WEST_1,
            "resource_3",
            "",
        )

    def test_is_muted_single_account(self):
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert not (
            is_muted(
                mutelist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test", ""
            )
        )

    def test_is_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = AWS_REGION_US_EAST_1

        assert is_muted_in_region(muted_regions, finding_region)

    def test_is_muted_in_region_wildcard(self):
        muted_regions = ["*"]
        finding_region = AWS_REGION_US_EAST_1

        assert is_muted_in_region(muted_regions, finding_region)

    def test_is_not_muted_in_region(self):
        muted_regions = [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        finding_region = "eu-west-2"

        assert not is_muted_in_region(muted_regions, finding_region)

    def test_is_muted_in_check(self):
        muted_checks = {
            "check_test": {
                "Regions": [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1],
                "Resources": ["*"],
            }
        }

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            is_muted_in_check(
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

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_public_access",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_no_mfa_delete",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_policy_public_write_access",
            AWS_REGION_US_EAST_1,
            "test-prowler",
            "",
        )

        assert not (
            is_muted_in_check(
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

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_code",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_not_publicly_accessible",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_cors_policy",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_url_public",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

        assert is_muted_in_check(
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

        assert is_muted_in_check(
            muted_checks,
            AWS_ACCOUNT_NUMBER,
            "awslambda_function_no_secrets_in_variables",
            AWS_REGION_US_EAST_1,
            "prowler",
            "",
        )

    def test_is_muted_tags(self):
        # Mutelist example
        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler",
            "environment=dev",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_US_EAST_1,
            "prowler-test",
            "environment=dev | project=prowler",
        )

        assert not (
            is_muted(
                mutelist,
                AWS_ACCOUNT_NUMBER,
                "check_test",
                "us-east-2",
                "test",
                "environment=pro",
            )
        )

    def test_is_muted_specific_account_with_other_account_excepted(self):

        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "check_test",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

        assert not is_muted(
            mutelist,
            "111122223333",
            "check_test",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

    def test_is_muted_complex_mutelist(self):

        mutelist = {
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

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "test_check",
            AWS_REGION_EU_WEST_1,
            "prowler-logs",
            "environment=dev",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "ecs_task_definitions_no_environment_secrets",
            AWS_REGION_EU_WEST_1,
            "prowler",
            "environment=dev",
        )

        assert is_muted(
            mutelist,
            AWS_ACCOUNT_NUMBER,
            "s3_bucket_object_versioning",
            AWS_REGION_EU_WEST_1,
            "prowler-logs",
            "environment=dev",
        )

    def test_is_muted_in_tags(self):
        mutelist_tags = ["environment=dev", "project=prowler"]

        assert is_muted_in_tags(mutelist_tags, "environment=dev")

        assert is_muted_in_tags(
            mutelist_tags,
            "environment=dev | project=prowler",
        )

        assert not (
            is_muted_in_tags(
                mutelist_tags,
                "environment=pro",
            )
        )

    def test_is_muted_in_tags_regex(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]

        assert is_muted_in_tags(
            mutelist_tags,
            "environment=test | proj=prowler",
        )

        assert is_muted_in_tags(
            mutelist_tags,
            "env=prod | project=prowler",
        )

        assert not is_muted_in_tags(
            mutelist_tags,
            "environment=prod | project=myproj",
        )

    def test_is_muted_in_tags_with_no_tags_in_finding(self):
        mutelist_tags = ["environment=(dev|test)", ".*=prowler"]
        finding_tags = ""

        assert not is_muted_in_tags(mutelist_tags, finding_tags)

    def test_is_excepted(self):
        # Mutelist example
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

    def test_is_excepted_only_in_account(self):

        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": [],
            "Resources": [],
            "Tags": [],
        }

        assert is_excepted(
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

        assert is_excepted(
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

        assert is_excepted(
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

        assert is_excepted(
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

        assert is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
        )

        assert not is_excepted(
            exceptions,
            "111122223333",
            AWS_REGION_EU_CENTRAL_1,
            "resource_1",
            "environment=test",
        )

        assert not is_excepted(
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
        assert is_excepted(
            exceptions, AWS_ACCOUNT_NUMBER, "eu-south-2", "test", "environment=test"
        )
        assert not is_excepted(
            exceptions, AWS_ACCOUNT_NUMBER, "eu-south-2", "test", None
        )

    def test_is_not_excepted(self):
        exceptions = {
            "Accounts": [AWS_ACCOUNT_NUMBER],
            "Regions": ["eu-central-1", "eu-south-3"],
            "Resources": ["test"],
            "Tags": ["environment=test", "project=.*"],
        }

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

    def test_is_excepted_all_empty(self):
        exceptions = {
            "Accounts": [],
            "Regions": [],
            "Resources": [],
            "Tags": [],
        }

        assert not is_excepted(
            exceptions,
            AWS_ACCOUNT_NUMBER,
            "eu-south-2",
            "test",
            "environment=test",
        )

    def test_is_muted_in_resource(self):
        mutelist_resources = ["prowler", "^test", "prowler-pro"]

        assert is_muted_in_resource(mutelist_resources, "prowler")
        assert is_muted_in_resource(mutelist_resources, "prowler-test")
        assert is_muted_in_resource(mutelist_resources, "test-prowler")
        assert not is_muted_in_resource(mutelist_resources, "random")

    def test_is_muted_in_resource_starting_by_star(self):
        allowlist_resources = ["*.es"]

        assert is_muted_in_resource(allowlist_resources, "google.es")
