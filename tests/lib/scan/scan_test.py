import unittest
from unittest import mock

from prowler.lib.scan.scan import Scan, get_service_checks_to_execute
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import set_mocked_aws_provider


class Test_Scan(unittest.TestCase):

    def test_init(self):
        provider = set_mocked_aws_provider()
        checks_to_execute = {
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
        scan = Scan(provider, checks_to_execute)

        assert scan.provider == provider
        assert scan.checks_to_execute == checks_to_execute
        assert scan.service_checks_to_execute == get_service_checks_to_execute(
            checks_to_execute
        )
        assert scan.service_checks_completed == {}
        assert scan.progress == 0
        assert scan.get_completed_services() == set()
        assert scan.get_completed_checks() == set()

    def setUp(self):
        self.mock_provider = set_mocked_aws_provider()

        self.patcher1 = mock.patch("prowler.lib.scan.scan.execute", autospec=True)
        self.mock_execute = self.patcher1.start()
        self.addCleanup(self.patcher1.stop)

        self.patcher2 = mock.patch(
            "prowler.lib.scan.scan.update_audit_metadata", autospec=True
        )
        self.mock_update_audit_metadata = self.patcher2.start()
        self.addCleanup(self.patcher2.stop)

        self.patcher3 = mock.patch("prowler.lib.logger.logger", autospec=True)
        self.mock_logger = self.patcher3.start()
        self.addCleanup(self.patcher3.stop)

        self.patcher4 = mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=self.mock_provider,
        )
        self.mock_global_provider = self.patcher4.start()
        self.addCleanup(self.patcher4.stop)

        self.findings = [
            generate_finding_output(
                status="PASS",
                status_extended="status-extended",
                resource_uid="resource-123",
                resource_name="Example Resource",
                resource_details="Detailed information about the resource",
                resource_tags="tag1,tag2",
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
        ]

        self.mock_execute.side_effect = [self.findings, self.findings]

    def test_scan(self):
        checks_to_execute = {"accessanalyzer_enabled", "ec2_instance_public_ip"}
        custom_checks_metadata = {}

        # Create a Scan object
        scan = Scan(self.mock_provider, checks_to_execute)

        # Execute the scan
        results = list(scan.scan(custom_checks_metadata))

        # Verify that execute was called twice
        assert self.mock_execute.call_count == 2

        assert len(results) == 2
        assert results[0][1] == self.findings
        assert results[1][1] == self.findings

        # verify that update_audit_metadata was called twice
        assert self.mock_update_audit_metadata.call_count == 2

        # verify that the progress is 1.0
        assert scan.progress == 1.0
        assert scan._number_of_checks_completed == 2

        # Verify that the findings are correct
        assert scan.findings == self.findings + self.findings

        # verify that the service_checks_completed is correct
        self.mock_logger.error.assert_not_called()


if __name__ == "__main__":
    unittest.main()
