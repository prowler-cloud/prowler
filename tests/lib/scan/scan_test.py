from unittest import mock

import pytest

from prowler.lib.scan.scan import Scan, get_service_checks_to_execute
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import set_mocked_aws_provider

finding = generate_finding_output(
    status="PASS",
    status_extended="status-extended",
    resource_uid="resource-123",
    resource_name="Example Resource",
    resource_details="Detailed information about the resource",
    resource_tags={"tag1": "value1", "tag2": "value2"},
    partition="aws",
    description="Description of the finding",
    risk="High",
    related_url="http://example.com",
    remediation_recommendation_text="Recommendation text",
    remediation_recommendation_url="http://example.com/remediation",
    remediation_code_nativeiac="native-iac-code",
    remediation_code_terraform="terraform-code",
    remediation_code_other="other-code",
    remediation_code_cli="cli-code",
    compliance={"compliance_key": "compliance_value"},
    categories="category1,category2",
    depends_on="dependency",
    related_to="related finding",
    notes="Notes about the finding",
)


@pytest.fixture
def mock_provider():
    return set_mocked_aws_provider()


@pytest.fixture
def mock_execute():
    with mock.patch("prowler.lib.scan.scan.execute", autospec=True) as mock_exec:
        findings = [finding]
        mock_exec.side_effect = lambda *args, **kwargs: findings
        yield mock_exec


@pytest.fixture
def mock_logger():
    with mock.patch("prowler.lib.logger.logger", autospec=True) as mock_log:
        yield mock_log


@pytest.fixture
def mock_global_provider(mock_provider):
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=mock_provider,
    ):
        yield mock_provider


@pytest.fixture
def mock_generate_output():
    with mock.patch(
        "prowler.lib.outputs.finding.Finding.generate_output", autospec=True
    ) as mock_gen_output:
        mock_gen_output.side_effect = lambda provider, finding: finding
        yield mock_gen_output


class TestScan:
    def test_init(mock_provider):
        checks_to_execute = {
            "workspaces_vpc_2private_1public_subnets_nat",
            "workspaces_vpc_2private_1public_subnets_nat",
            "accessanalyzer_enabled",
            "accessanalyzer_enabled_without_findings",
            "account_maintain_current_contact_details",
            "account_maintain_different_contact_details_to_security_billing_and_operations",
            "account_security_contact_information_is_registered",
            "account_security_questions_are_registered_in_the_aws_account",
            "acm_certificates_expiration_check",
            "acm_certificates_transparency_logs_enabled",
            "apigateway_restapi_authorizers_enabled",
            "apigateway_restapi_client_certificate_enabled",
            "apigateway_restapi_logging_enabled",
            "apigateway_restapi_public",
            "awslambda_function_not_publicly_accessible",
            "awslambda_function_url_cors_policy",
            "awslambda_function_url_public",
            "awslambda_function_using_supported_runtimes",
            "backup_plans_exist",
            "backup_reportplans_exist",
            "backup_vaults_encrypted",
            "backup_vaults_exist",
            "cloudformation_stack_outputs_find_secrets",
            "cloudformation_stacks_termination_protection_enabled",
            "cloudwatch_cross_account_sharing_disabled",
            "cloudwatch_log_group_kms_encryption_enabled",
            "cloudwatch_log_group_no_secrets_in_logs",
            "cloudwatch_log_group_retention_policy_specific_days_enabled",
            "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
            "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
            "cloudwatch_log_metric_filter_authentication_failures",
            "cloudwatch_log_metric_filter_aws_organizations_changes",
            "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
            "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
            "cloudwatch_log_metric_filter_policy_changes",
            "cloudwatch_log_metric_filter_root_usage",
            "cloudwatch_log_metric_filter_security_group_changes",
            "cloudwatch_log_metric_filter_sign_in_without_mfa",
            "cloudwatch_log_metric_filter_unauthorized_api_calls",
            "codeartifact_packages_external_public_publishing_disabled",
            "codebuild_project_older_90_days",
            "codebuild_project_user_controlled_buildspec",
            "cognito_identity_pool_guest_access_disabled",
            "cognito_user_pool_advanced_security_enabled",
            "cognito_user_pool_blocks_compromised_credentials_sign_in_attempts",
            "cognito_user_pool_blocks_potential_malicious_sign_in_attempts",
            "cognito_user_pool_client_prevent_user_existence_errors",
            "cognito_user_pool_client_token_revocation_enabled",
            "cognito_user_pool_deletion_protection_enabled",
            "cognito_user_pool_mfa_enabled",
            "cognito_user_pool_password_policy_lowercase",
            "cognito_user_pool_password_policy_minimum_length_14",
            "cognito_user_pool_password_policy_number",
            "cognito_user_pool_password_policy_symbol",
            "cognito_user_pool_password_policy_uppercase",
            "cognito_user_pool_self_registration_disabled",
            "cognito_user_pool_temporary_password_expiration",
            "cognito_user_pool_waf_acl_attached",
            "config_recorder_all_regions_enabled",
        }
        scan = Scan(mock_provider, checks_to_execute)

        assert scan.provider == mock_provider
        # Check that the checks to execute are sorted and without duplicates
        assert scan.checks_to_execute == [
            "accessanalyzer_enabled",
            "accessanalyzer_enabled_without_findings",
            "account_maintain_current_contact_details",
            "account_maintain_different_contact_details_to_security_billing_and_operations",
            "account_security_contact_information_is_registered",
            "account_security_questions_are_registered_in_the_aws_account",
            "acm_certificates_expiration_check",
            "acm_certificates_transparency_logs_enabled",
            "apigateway_restapi_authorizers_enabled",
            "apigateway_restapi_client_certificate_enabled",
            "apigateway_restapi_logging_enabled",
            "apigateway_restapi_public",
            "awslambda_function_not_publicly_accessible",
            "awslambda_function_url_cors_policy",
            "awslambda_function_url_public",
            "awslambda_function_using_supported_runtimes",
            "backup_plans_exist",
            "backup_reportplans_exist",
            "backup_vaults_encrypted",
            "backup_vaults_exist",
            "cloudformation_stack_outputs_find_secrets",
            "cloudformation_stacks_termination_protection_enabled",
            "cloudwatch_cross_account_sharing_disabled",
            "cloudwatch_log_group_kms_encryption_enabled",
            "cloudwatch_log_group_no_secrets_in_logs",
            "cloudwatch_log_group_retention_policy_specific_days_enabled",
            "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
            "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
            "cloudwatch_log_metric_filter_authentication_failures",
            "cloudwatch_log_metric_filter_aws_organizations_changes",
            "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
            "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
            "cloudwatch_log_metric_filter_policy_changes",
            "cloudwatch_log_metric_filter_root_usage",
            "cloudwatch_log_metric_filter_security_group_changes",
            "cloudwatch_log_metric_filter_sign_in_without_mfa",
            "cloudwatch_log_metric_filter_unauthorized_api_calls",
            "codeartifact_packages_external_public_publishing_disabled",
            "codebuild_project_older_90_days",
            "codebuild_project_user_controlled_buildspec",
            "cognito_identity_pool_guest_access_disabled",
            "cognito_user_pool_advanced_security_enabled",
            "cognito_user_pool_blocks_compromised_credentials_sign_in_attempts",
            "cognito_user_pool_blocks_potential_malicious_sign_in_attempts",
            "cognito_user_pool_client_prevent_user_existence_errors",
            "cognito_user_pool_client_token_revocation_enabled",
            "cognito_user_pool_deletion_protection_enabled",
            "cognito_user_pool_mfa_enabled",
            "cognito_user_pool_password_policy_lowercase",
            "cognito_user_pool_password_policy_minimum_length_14",
            "cognito_user_pool_password_policy_number",
            "cognito_user_pool_password_policy_symbol",
            "cognito_user_pool_password_policy_uppercase",
            "cognito_user_pool_self_registration_disabled",
            "cognito_user_pool_temporary_password_expiration",
            "cognito_user_pool_waf_acl_attached",
            "config_recorder_all_regions_enabled",
            "workspaces_vpc_2private_1public_subnets_nat",
        ]
        assert scan.service_checks_to_execute == get_service_checks_to_execute(
            checks_to_execute
        )
        assert scan.service_checks_completed == {}
        assert scan.progress == 0
        assert scan.get_completed_services() == set()
        assert scan.get_completed_checks() == set()

    def test_scan(
        mock_global_provider, mock_execute, mock_logger, mock_generate_output
    ):
        checks_to_execute = {"accessanalyzer_enabled", "ec2_instance_public"}
        custom_checks_metadata = {}

        # Create a Scan object
        scan = Scan(mock_global_provider, checks_to_execute)

        # Execute the scan
        results = list(scan.scan(custom_checks_metadata))

        # Verify that generate_output was called with the correct findings
        assert mock_generate_output.call_count == 2 * len(mock_execute.side_effect())

        # Verify that execute was called twice
        assert mock_execute.call_count == 2

        assert len(results) == 2
        assert results[0][1] == mock_execute.side_effect()
        assert results[1][1] == mock_execute.side_effect()

        # Check the audit progress for the last result
        assert results[1][0] == 100.0

        # Verify that the progress is 100.0
        assert scan.progress == 100.0  # 100% progress is 100
        assert scan._number_of_checks_completed == 2
        assert scan.service_checks_to_execute == {}
        assert scan.service_checks_completed == {
            "ec2": {"ec2_instance_public"},
            "accessanalyzer": {"accessanalyzer_enabled"},
        }

        # Verify that the findings are correct
        assert scan.findings == mock_execute.side_effect() + mock_execute.side_effect()

        # Verify that no error was logged
        mock_logger.error.assert_not_called()
