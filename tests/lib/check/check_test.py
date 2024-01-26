import os
import pathlib
from importlib.machinery import FileFinder
from pkgutil import ModuleInfo

from boto3 import client
from fixtures.bulk_checks_metadata import test_bulk_checks_metadata
from mock import patch
from moto import mock_s3

from prowler.lib.check.check import (
    exclude_checks_to_run,
    exclude_services_to_run,
    list_categories,
    list_checks_json,
    list_modules,
    list_services,
    parse_checks_from_file,
    parse_checks_from_folder,
    recover_checks_from_provider,
    recover_checks_from_service,
    remove_custom_checks_module,
    update_audit_metadata,
)
from prowler.lib.check.models import load_check_metadata
from prowler.providers.aws.aws_provider import (
    get_checks_from_input_arn,
    get_regions_from_audit_resources,
)
from tests.providers.aws.audit_info_utils import set_mocked_aws_audit_info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

expected_packages = [
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_minimum_tls_version_12.storage_ensure_minimum_tls_version_12",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_key_rotation_90_days"
        ),
        name="prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder("/root_dir/prowler/providers/azure/services/storage"),
        name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys.storage_ensure_encryption_with_customer_managed_keys",
        ispkg=False,
    ),
]


def mock_walk_packages(*_):
    return expected_packages


def mock_list_modules(*_):
    modules = [
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_minimum_tls_version_12.storage_ensure_minimum_tls_version_12",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_key_rotation_90_days"
            ),
            name="prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys.storage_ensure_encryption_with_customer_managed_keys",
            ispkg=False,
        ),
    ]
    return modules


def mock_recover_checks_from_azure_provider(*_):
    return [
        (
            "defender_ensure_defender_for_app_services_is_on",
            "/root_dir/fake_path/defender/defender_ensure_defender_for_app_services_is_on",
        ),
        (
            "iam_subscription_roles_owner_custom_not_created",
            "/root_dir/fake_path/iam/iam_subscription_roles_owner_custom_not_created",
        ),
        (
            "iam_custom_role_has_permissions_to_administer_resource_locks",
            "/root_dir/fake_path/iam/iam_custom_role_has_permissions_to_administer_resource_locks",
        ),
        (
            "storage_default_network_access_rule_is_denied",
            "/root_dir/fake_path/storage/storage_default_network_access_rule_is_denied",
        ),
    ]


def mock_recover_checks_from_aws_provider(*_):
    return [
        (
            "accessanalyzer_enabled_without_findings",
            "/root_dir/fake_path/accessanalyzer/accessanalyzer_enabled_without_findings",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "/root_dir/fake_path/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        ),
    ]


def mock_recover_checks_from_aws_provider_lambda_service(*_):
    return [
        (
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "/root_dir/fake_path/awslambda/awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "awslambda_function_no_secrets_in_code",
            "/root_dir/fake_path/awslambda/awslambda_function_no_secrets_in_code",
        ),
    ]


def mock_recover_checks_from_aws_provider_elb_service(*_):
    return [
        (
            "elb_insecure_ssl_ciphers",
            "/root_dir/fake_path/elb/elb_insecure_ssl_ciphers",
        ),
        (
            "elb_internet_facing",
            "/root_dir/fake_path/elb/elb_internet_facing",
        ),
        (
            "elb_logging_enabled",
            "/root_dir/fake_path/elb/elb_logging_enabled",
        ),
    ]


def mock_recover_checks_from_aws_provider_efs_service(*_):
    return [
        (
            "efs_encryption_at_rest_enabled",
            "/root_dir/fake_path/efs/efs_encryption_at_rest_enabled",
        ),
        (
            "efs_have_backup_enabled",
            "/root_dir/fake_path/efs/efs_have_backup_enabled",
        ),
        (
            "efs_not_publicly_accessible",
            "/root_dir/fake_path/efs/efs_not_publicly_accessible",
        ),
    ]


def mock_recover_checks_from_aws_provider_iam_service(*_):
    return [
        (
            "iam_customer_attached_policy_no_administrative_privileges",
            "/root_dir/fake_path/iam/iam_customer_attached_policy_no_administrative_privileges",
        ),
        (
            "iam_check_saml_providers_sts",
            "/root_dir/fake_path/iam/iam_check_saml_providers_sts",
        ),
        (
            "iam_password_policy_minimum_length_14",
            "/root_dir/fake_path/iam/iam_password_policy_minimum_length_14",
        ),
    ]


def mock_recover_checks_from_aws_provider_s3_service(*_):
    return [
        (
            "s3_account_level_public_access_blocks",
            "/root_dir/fake_path/s3/s3_account_level_public_access_blocks",
        ),
        (
            "s3_bucket_acl_prohibited",
            "/root_dir/fake_path/s3/s3_bucket_acl_prohibited",
        ),
        (
            "s3_bucket_policy_public_write_access",
            "/root_dir/fake_path/s3/s3_bucket_policy_public_write_access",
        ),
    ]


def mock_recover_checks_from_aws_provider_cloudwatch_service(*_):
    return [
        (
            "cloudwatch_changes_to_network_acls_alarm_configured",
            "/root_dir/fake_path/cloudwatch/cloudwatch_changes_to_network_acls_alarm_configured",
        ),
        (
            "cloudwatch_changes_to_network_gateways_alarm_configured",
            "/root_dir/cloudwatch/cloudwatch_changes_to_network_gateways_alarm_configured",
        ),
        (
            "cloudwatch_changes_to_network_route_tables_alarm_configured",
            "/root_dir/fake_path/cloudwatch/cloudwatch_changes_to_network_route_tables_alarm_configured",
        ),
    ]


def mock_recover_checks_from_aws_provider_ec2_service(*_):
    return [
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "/root_dir/fake_path/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        ),
        (
            "ec2_networkacl_allow_ingress_any_port",
            "/root_dir/fake_path/ec2/ec2_networkacl_allow_ingress_any_port",
        ),
        (
            "ec2_ami_public",
            "/root_dir/fake_path/ec2/ec2_ami_public",
        ),
    ]


def mock_recover_checks_from_aws_provider_rds_service(*_):
    return [
        (
            "rds_instance_backup_enabled",
            "/root_dir/fake_path/rds/rds_instance_backup_enabled",
        ),
        (
            "rds_instance_deletion_protection",
            "/root_dir/fake_path/rds/rds_instance_deletion_protection",
        ),
        (
            "rds_snapshots_public_access",
            "/root_dir/fake_path/rds/rds_snapshots_public_access",
        ),
    ]


def mock_recover_checks_from_aws_provider_cognito_service(*_):
    return []


class Test_Check:
    def test_load_check_metadata(self):
        test_cases = [
            {
                "input": {
                    "metadata_path": f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/metadata.json",
                },
                "expected": {
                    "CheckID": "iam_user_accesskey_unused",
                    "CheckTitle": "Ensure Access Keys unused are disabled",
                    "ServiceName": "iam",
                    "Severity": "low",
                },
            }
        ]
        for test in test_cases:
            metadata_path = test["input"]["metadata_path"]
            check_metadata = load_check_metadata(metadata_path)
            assert check_metadata.CheckID == test["expected"]["CheckID"]
            assert check_metadata.CheckTitle == test["expected"]["CheckTitle"]
            assert check_metadata.ServiceName == test["expected"]["ServiceName"]
            assert check_metadata.Severity == test["expected"]["Severity"]

    def test_parse_checks_from_file(self):
        test_cases = [
            {
                "input": {
                    "path": f"{pathlib.Path().absolute()}/tests/lib/check/fixtures/checklistA.json",
                    "provider": "aws",
                },
                "expected": {"check11", "check12", "check7777"},
            }
        ]
        for test in test_cases:
            check_file = test["input"]["path"]
            provider = test["input"]["provider"]
            assert parse_checks_from_file(check_file, provider) == test["expected"]

    @mock_s3
    def test_parse_checks_from_folder(self):
        test_checks_folder = (
            f"{pathlib.Path().absolute()}/tests/lib/check/fixtures/checks_folder"
        )
        # Create bucket and upload checks folder
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        # Iterate through the files in the folder and upload each one
        for subdir, _, files in os.walk(test_checks_folder):
            for file in files:
                check = subdir.split("/")[-1]
                full_path = os.path.join(subdir, file)
                with open(full_path, "rb") as data:
                    s3_client.upload_fileobj(
                        data, "test", f"checks_folder/{check}/{file}"
                    )
        test_cases = [
            {
                "input": {
                    "path": test_checks_folder,
                    "provider": "aws",
                },
                "expected": 3,
            },
            {
                "input": {
                    "path": "s3://test/checks_folder/",
                    "provider": "aws",
                },
                "expected": 3,
            },
        ]
        for test in test_cases:
            check_folder = test["input"]["path"]
            provider = test["input"]["provider"]
            assert (
                parse_checks_from_folder(
                    set_mocked_aws_audit_info(), check_folder, provider
                )
                == test["expected"]
            )
            remove_custom_checks_module(check_folder, provider)

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

    def test_exclude_services_to_run(self):
        test_cases = [
            {
                "input": {
                    "checks_to_run": {
                        "iam_user_console_access_unused",
                        "iam_user_accesskey_unused",
                    },
                    "excluded_services": {"ec2"},
                    "provider": "aws",
                },
                "expected": {
                    "iam_user_console_access_unused",
                    "iam_user_accesskey_unused",
                },
            },
            {
                "input": {
                    "checks_to_run": {
                        "iam_user_console_access_unused",
                        "iam_user_accesskey_unused",
                    },
                    "excluded_services": {"iam"},
                    "provider": "aws",
                },
                "expected": set(),
            },
        ]
        for test in test_cases:
            excluded_services = test["input"]["excluded_services"]
            checks_to_run = test["input"]["checks_to_run"]
            provider = test["input"]["provider"]
            assert (
                exclude_services_to_run(checks_to_run, excluded_services, provider)
                == test["expected"]
            )

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_azure_provider,
    )
    def test_list_azure_services(self):
        provider = "azure"
        expected_services = {"defender", "iam", "storage"}
        listed_services = list_services(provider)
        assert listed_services == sorted(expected_services)

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider,
    )
    def test_list_aws_services(self):
        provider = "azure"
        expected_services = {"accessanalyzer", "awslambda", "ec2"}
        listed_services = list_services(provider)
        assert listed_services == sorted(expected_services)

    def test_list_categories(self):
        expected_categories = {
            "secrets",
            "forensics-ready",
            "encryption",
            "internet-exposed",
            "trustboundaries",
        }
        listed_categories = list_categories(test_bulk_checks_metadata)
        assert listed_categories == expected_categories

    @patch("prowler.lib.check.check.list_modules", new=mock_list_modules)
    def test_recover_checks_from_provider(self):
        provider = "azure"
        service = "storage"
        expected_checks = [
            (
                "storage_ensure_minimum_tls_version_12",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12",
            ),
            (
                "storage_key_rotation_90_days",
                "/root_dir/prowler/providers/azure/services/storage/storage_key_rotation_90_days",
            ),
            (
                "storage_ensure_encryption_with_customer_managed_keys",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys",
            ),
        ]
        returned_checks = recover_checks_from_provider(provider, service)
        assert returned_checks == expected_checks

    @patch("prowler.lib.check.check.walk_packages", new=mock_walk_packages)
    def test_list_modules(self):
        provider = "azure"
        service = "storage"
        expected_modules = list_modules(provider, service)
        assert expected_modules == expected_packages

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider,
    )
    def test_recover_checks_from_service(self):
        service_list = ["accessanalyzer", "awslambda", "ec2"]
        provider = "aws"
        expected_checks = {
            "accessanalyzer_enabled_without_findings",
            "awslambda_function_url_cors_policy",
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        }
        recovered_checks = recover_checks_from_service(service_list, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_elb_service,
    )
    def test_get_checks_from_input_arn_elb(self):
        audit_resources = [
            f"arn:aws:elasticloadbalancing:us-east-1:{AWS_ACCOUNT_NUMBER}:loadbalancer/test"
        ]
        provider = "aws"
        expected_checks = [
            "elb_insecure_ssl_ciphers",
            "elb_internet_facing",
            "elb_logging_enabled",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_efs_service,
    )
    def test_get_checks_from_input_arn_efs(self):
        audit_resources = [
            f"arn:aws:elasticfilesystem:us-east-1:{AWS_ACCOUNT_NUMBER}:file-system/fs-01234567"
        ]
        provider = "aws"
        expected_checks = [
            "efs_encryption_at_rest_enabled",
            "efs_have_backup_enabled",
            "efs_not_publicly_accessible",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_lambda_service,
    )
    def test_get_checks_from_input_arn_lambda(self):
        audit_resources = ["arn:aws:lambda:us-east-1:123456789:function:test-lambda"]
        provider = "aws"
        expected_checks = [
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "awslambda_function_no_secrets_in_code",
            "awslambda_function_url_cors_policy",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_iam_service,
    )
    def test_get_checks_from_input_arn_iam(self):
        audit_resources = [f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/user-name"]
        provider = "aws"
        expected_checks = [
            "iam_check_saml_providers_sts",
            "iam_customer_attached_policy_no_administrative_privileges",
            "iam_password_policy_minimum_length_14",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_s3_service,
    )
    def test_get_checks_from_input_arn_s3(self):
        audit_resources = ["arn:aws:s3:::bucket-name"]
        provider = "aws"
        expected_checks = [
            "s3_account_level_public_access_blocks",
            "s3_bucket_acl_prohibited",
            "s3_bucket_policy_public_write_access",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_cloudwatch_service,
    )
    def test_get_checks_from_input_arn_cloudwatch(self):
        audit_resources = [
            f"arn:aws:logs:us-east-1:{AWS_ACCOUNT_NUMBER}:destination:testDestination"
        ]
        provider = "aws"
        expected_checks = [
            "cloudwatch_changes_to_network_acls_alarm_configured",
            "cloudwatch_changes_to_network_gateways_alarm_configured",
            "cloudwatch_changes_to_network_route_tables_alarm_configured",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_cognito_service,
    )
    def test_get_checks_from_input_arn_cognito(self):
        audit_resources = [
            f"arn:aws:cognito-idp:us-east-1:{AWS_ACCOUNT_NUMBER}:userpool/test"
        ]
        provider = "aws"
        expected_checks = []
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_security_group(self):
        audit_resources = [
            f"arn:aws:ec2:us-east-1:{AWS_ACCOUNT_NUMBER}:security-group/sg-1111111111"
        ]
        provider = "aws"
        expected_checks = ["ec2_securitygroup_allow_ingress_from_internet_to_any_port"]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_acl(self):
        audit_resources = [
            f"arn:aws:ec2:us-west-2:{AWS_ACCOUNT_NUMBER}:network-acl/acl-1"
        ]
        provider = "aws"
        expected_checks = ["ec2_networkacl_allow_ingress_any_port"]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_rds_service,
    )
    def test_get_checks_from_input_arn_rds_snapshots(self):
        audit_resources = [
            f"arn:aws:rds:us-east-2:{AWS_ACCOUNT_NUMBER}:snapshot:rds:snapshot-1"
        ]
        provider = "aws"
        expected_checks = ["rds_snapshots_public_access"]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_ami(self):
        audit_resources = [f"arn:aws:ec2:us-west-2:{AWS_ACCOUNT_NUMBER}:image/ami-1"]
        provider = "aws"
        expected_checks = ["ec2_ami_public"]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    def test_get_regions_from_audit_resources_with_regions(self):
        audit_resources = [
            f"arn:aws:lambda:us-east-1:{AWS_ACCOUNT_NUMBER}:function:test-lambda",
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/test",
            f"arn:aws:ec2:eu-west-1:{AWS_ACCOUNT_NUMBER}:security-group/sg-test",
            "arn:aws:s3:::bucket-name",
            "arn:aws:apigateway:us-east-2::/restapis/api-id/stages/stage-name",
        ]
        expected_regions = {"us-east-1", "eu-west-1", "us-east-2"}
        recovered_regions = get_regions_from_audit_resources(audit_resources)
        assert recovered_regions == expected_regions

    def test_get_regions_from_audit_resources_without_regions(self):
        audit_resources = ["arn:aws:s3:::bucket-name"]
        recovered_regions = get_regions_from_audit_resources(audit_resources)
        assert not recovered_regions

    # def test_parse_checks_from_compliance_framework_two(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": ["cis_v1.4_aws", "ens_v3_aws"]},
    #         "expected": {
    #             "vpc_flow_logs_enabled",
    #             "ec2_ebs_snapshot_encryption",
    #             "iam_user_mfa_enabled_console_access",
    #             "cloudtrail_multi_region_enabled",
    #             "ec2_elbv2_insecure_ssl_ciphers",
    #             "guardduty_is_enabled",
    #             "s3_bucket_default_encryption",
    #             "cloudfront_distributions_https_enabled",
    #             "iam_avoid_root_usage",
    #             "s3_bucket_secure_transport_policy",
    #         },
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir_path",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    # def test_parse_checks_from_compliance_framework_one(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": ["cis_v1.4_aws"]},
    #         "expected": {
    #             "iam_user_mfa_enabled_console_access",
    #             "s3_bucket_default_encryption",
    #             "iam_avoid_root_usage",
    #         },
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    # def test_parse_checks_from_compliance_framework_no_compliance(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": []},
    #         "expected": set(),
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    def test_update_audit_metadata_complete(self):
        from prowler.providers.common.models import Audit_Metadata

        # Set the expected checks to run
        expected_checks = ["iam_administrator_access_with_mfa"]
        services_executed = {"iam"}
        checks_executed = {"iam_administrator_access_with_mfa"}

        # Set an empty Audit_Metadata
        audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        )

        audit_metadata = update_audit_metadata(
            audit_metadata, services_executed, checks_executed
        )

        assert audit_metadata.audit_progress == float(100)
        assert audit_metadata.services_scanned == 1
        assert audit_metadata.expected_checks == expected_checks
        assert audit_metadata.completed_checks == 1

    def test_update_audit_metadata_50(self):
        from prowler.providers.common.models import Audit_Metadata

        # Set the expected checks to run
        expected_checks = [
            "iam_administrator_access_with_mfa",
            "iam_support_role_created",
        ]
        services_executed = {"iam"}
        checks_executed = {"iam_administrator_access_with_mfa"}

        # Set an empty Audit_Metadata
        audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        )

        audit_metadata = update_audit_metadata(
            audit_metadata, services_executed, checks_executed
        )

        assert audit_metadata.audit_progress == float(50)
        assert audit_metadata.services_scanned == 1
        assert audit_metadata.expected_checks == expected_checks
        assert audit_metadata.completed_checks == 1

    def test_list_checks_json_aws_lambda_and_s3(self):
        provider = "aws"
        check_list = {
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "awslambda_function_no_secrets_in_code",
            "awslambda_function_no_secrets_in_variables",
            "awslambda_function_not_publicly_accessible",
            "awslambda_function_url_cors_policy",
            "awslambda_function_url_public",
            "awslambda_function_using_supported_runtimes",
        }
        checks_json = list_checks_json(provider, sorted(check_list))
        assert (
            checks_json
            == '{\n  "aws": [\n    "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",\n    "awslambda_function_no_secrets_in_code",\n    "awslambda_function_no_secrets_in_variables",\n    "awslambda_function_not_publicly_accessible",\n    "awslambda_function_url_cors_policy",\n    "awslambda_function_url_public",\n    "awslambda_function_using_supported_runtimes"\n  ]\n}'
        )
