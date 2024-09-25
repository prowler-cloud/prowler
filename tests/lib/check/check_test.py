import json
import os
import pathlib
from importlib.machinery import FileFinder
from logging import ERROR
from pkgutil import ModuleInfo
from unittest import mock

from boto3 import client
from mock import Mock, patch
from moto import mock_aws

from prowler.lib.check.check import (
    exclude_checks_to_run,
    exclude_services_to_run,
    execute,
    execute_checks,
    list_categories,
    list_checks_json,
    list_services,
    parse_checks_from_file,
    parse_checks_from_folder,
    remove_custom_checks_module,
    update_audit_metadata,
)
from prowler.lib.check.models import load_check_metadata
from prowler.lib.check.utils import (
    list_modules,
    recover_checks_from_provider,
    recover_checks_from_service,
)
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    Analyzer,
)
from tests.lib.check.fixtures.bulk_checks_metadata import test_bulk_checks_metadata
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# AWS_ACCOUNT_NUMBER = "123456789012"
# AWS_REGION = "us-east-1"

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
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_private_endpoints_in_storage_accounts"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_private_endpoints_in_storage_accounts.storage_ensure_private_endpoints_in_storage_accounts",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_soft_delete_is_enabled"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled",
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
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encrypted_with_cmk"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encryption_enabled"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_auditing_retention_90_days"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_vulnerability_assessment_enabled",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_vulnerability_assessment_enabled"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_vulnerability_assessment_enabled.sqlserver_vulnerability_assessment_enabled",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_periodic_recurring_scans_enabled",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_periodic_recurring_scans_enabled"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_periodic_recurring_scans_enabled.sqlserver_va_periodic_recurring_scans_enabled",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_scan_reports_configured"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_emails_notifications_admins_enabled",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_emails_notifications_admins_enabled"
        ),
        name="prowler.providers.azure.services.sqlserver.sqlserver_va_emails_notifications_admins_enabled.sqlserver_va_emails_notifications_admins_enabled",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/postgresql"
        ),
        name="prowler.providers.azure.services.postgresql.postgresql_flexible_server_enforce_ssl_enabled",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/postgresql/postgresql_flexible_server_enforce_ssl_enabled"
        ),
        name="prowler.providers.azure.services.postgresql.postgresql_flexible_server_enforce_ssl_enabled.postgresql_flexible_server_enforce_ssl_enabled",
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
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_private_endpoints_in_storage_accounts"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_private_endpoints_in_storage_accounts.storage_ensure_private_endpoints_in_storage_accounts",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_soft_delete_is_enabled"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled",
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
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encrypted_with_cmk"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encryption_enabled"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_auditing_retention_90_days"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_vulnerability_assessment_enabled",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_vulnerability_assessment_enabled"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_vulnerability_assessment_enabled.sqlserver_vulnerability_assessment_enabled",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_periodic_recurring_scans_enabled",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_periodic_recurring_scans_enabled"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_periodic_recurring_scans_enabled.sqlserver_va_periodic_recurring_scans_enabled",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_scan_reports_configured"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_emails_notifications_admins_enabled",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_emails_notifications_admins_enabled"
            ),
            name="prowler.providers.azure.services.sqlserver.sqlserver_va_emails_notifications_admins_enabled.sqlserver_va_emails_notifications_admins_enabled",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/postgresql"
            ),
            name="prowler.providers.azure.services.postgresql.postgresql_flexible_server_enforce_ssl_enabled",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/postgresql/postgresql_flexible_server_enforce_ssl_enabled"
            ),
            name="prowler.providers.azure.services.postgresql.postgresql_flexible_server_enforce_ssl_enabled.postgresql_flexible_server_enforce_ssl_enabled",
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


class TestCheck:
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

    @mock_aws
    def test_parse_checks_from_folder(self):
        test_checks_folder = (
            f"{pathlib.Path().absolute()}/tests/lib/check/fixtures/checks_folder"
        )
        # Create bucket and upload checks folder
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
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
                "expected": {"check11", "check12", "check7777"},
            },
            {
                "input": {
                    "path": "s3://test/checks_folder/",
                    "provider": "aws",
                },
                "expected": {"check11", "check12", "check7777"},
            },
        ]

        aws_provider = AwsProvider()
        for test in test_cases:
            check_folder = test["input"]["path"]
            provider = test["input"]["provider"]
            assert (
                parse_checks_from_folder(aws_provider, check_folder) == test["expected"]
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

    @patch("prowler.lib.check.utils.list_modules", new=mock_list_modules)
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
                "storage_ensure_private_endpoints_in_storage_accounts",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_private_endpoints_in_storage_accounts",
            ),
            (
                "storage_ensure_soft_delete_is_enabled",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_soft_delete_is_enabled",
            ),
            (
                "storage_ensure_encryption_with_customer_managed_keys",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys",
            ),
            (
                "sqlserver_tde_encrypted_with_cmk",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encrypted_with_cmk",
            ),
            (
                "sqlserver_tde_encryption_enabled",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_tde_encryption_enabled",
            ),
            (
                "sqlserver_auditing_retention_90_days",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_auditing_retention_90_days",
            ),
            (
                "sqlserver_vulnerability_assessment_enabled",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_vulnerability_assessment_enabled",
            ),
            (
                "sqlserver_va_periodic_recurring_scans_enabled",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_periodic_recurring_scans_enabled",
            ),
            (
                "sqlserver_va_scan_reports_configured",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_scan_reports_configured",
            ),
            (
                "sqlserver_va_emails_notifications_admins_enabled",
                "/root_dir/prowler/providers/azure/services/sqlserver/sqlserver_va_emails_notifications_admins_enabled",
            ),
            (
                "postgresql_flexible_server_enforce_ssl_enabled",
                "/root_dir/prowler/providers/azure/services/postgresql/postgresql_flexible_server_enforce_ssl_enabled",
            ),
        ]
        returned_checks = recover_checks_from_provider(provider, service)
        assert returned_checks == expected_checks

    @patch("prowler.lib.check.utils.walk_packages", new=mock_walk_packages)
    def test_list_modules(self):
        provider = "azure"
        service = "storage"
        expected_modules = list_modules(provider, service)
        assert expected_modules == expected_packages

    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
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

    def test_execute(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.region = AWS_REGION_US_EAST_1
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region=AWS_REGION_US_EAST_1,
            )
        ]
        finding = Mock()
        finding.status = "PASS"
        findings = [finding]
        check = Mock()
        check.CheckID = "test-check"
        check.execute = Mock(return_value=findings)

        with patch("prowler.lib.check.check.execute", return_value=findings), patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            accessanalyzer_client,
        ):
            findings = execute(
                check=check,
                global_provider=set_mocked_aws_provider(
                    expected_checks=["accessanalyzer_enabled"]
                ),
                custom_checks_metadata=None,
                output_options=None,
            )
            assert len(findings) == 1

    def test_execute_with_filtering_status(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.region = AWS_REGION_US_EAST_1
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region=AWS_REGION_US_EAST_1,
            )
        ]
        status = ["PASS"]
        check = mock.MagicMock()
        check.CheckID = "accessanalyzer_enabled"
        check.Status = "PASS"
        output_options = mock.MagicMock()
        output_options.status = status
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            accessanalyzer_client,
        ):
            findings = execute(
                check=check,
                global_provider=set_mocked_aws_provider(
                    expected_checks=["accessanalyzer_enabled"]
                ),
                custom_checks_metadata=None,
                output_options=output_options,
            )
            assert len(findings) == 0

    def test_aws_checks_metadata_is_valid(self):
        # Check if the checkID in the metadata.json of the checks is correct
        # Define the base directory for the checks
        base_directory = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "../../../", "prowler/providers/aws/services"
            )
        )
        self.verify_metadata_check_id(base_directory)

    def test_azure_checks_metadata_is_valid(self):
        # Check if the checkID in the metadata.json of the checks is correct
        # Define the base directory for the checks
        base_directory = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../../",
                "prowler/providers/azure/services",
            )
        )
        self.verify_metadata_check_id(base_directory)

    def test_gcp_checks_metadata_is_valid(self):
        # Check if the checkID in the metadata.json of the checks is correct
        # Define the base directory for the checks
        base_directory = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "../../../", "prowler/providers/gcp/services"
            )
        )
        self.verify_metadata_check_id(base_directory)

    def test_kubernetes_checks_metadata_is_valid(self):
        # Check if the checkID in the metadata.json of the checks is correct
        # Define the base directory for the checks
        base_directory = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../../",
                "prowler/providers/kubernetes/services",
            )
        )
        self.verify_metadata_check_id(base_directory)

    def verify_metadata_check_id(self, provider_path):
        # Walk through the base directory to find all service directories
        for root, dirs, _ in os.walk(provider_path):
            # We only want to look at directories that are direct children of the base directory
            if root == provider_path:
                for service_dir in dirs:
                    service_path = os.path.join(root, service_dir)

                    # Walk through each service directory to find check directories
                    for check_root, check_dirs, _ in os.walk(service_path):
                        for check_dir in check_dirs:
                            check_directory = os.path.join(check_root, check_dir)
                            metadata_file_name = f"{check_dir}.metadata.json"
                            metadata_file_path = os.path.join(
                                check_directory, metadata_file_name
                            )

                            if os.path.isfile(metadata_file_path):
                                # Read the JSON file
                                with open(metadata_file_path, "r") as f:
                                    data = json.load(f)

                                # Extract the CheckID field
                                check_id = data.get("CheckID", None)

                                # Compare CheckID to the check name
                                assert (
                                    check_id == check_dir
                                ), f"CheckID in metadata does not match the check name in {check_directory}. Found CheckID: {check_id}"

    def test_execute_check_exception_only_logs(self, caplog):
        caplog.set_level(ERROR)

        findings = []
        check = Mock()
        checks = ["test-check"]

        provider = mock.MagicMock()
        provider.type = "aws"

        output_options = mock.MagicMock()
        output_options.only_logs = True
        error = Exception()
        check.execute = Mock(side_effect=error)

        with patch("prowler.lib.check.check.execute", return_value=findings):
            assert (
                execute_checks(
                    checks,
                    provider,
                    custom_checks_metadata=None,
                    config_file=None,
                    output_options=output_options,
                )
                == findings
            )
            assert caplog.record_tuples == [
                ("root", 40, f"Check '{checks[0]}' was not found for the AWS provider")
            ]
