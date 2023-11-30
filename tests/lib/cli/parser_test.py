import uuid
from argparse import ArgumentTypeError

import pytest
from mock import patch

from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.providers.azure.lib.arguments.arguments import validate_azure_region

prowler_command = "prowler"

# capsys
# https://docs.pytest.org/en/7.1.x/how-to/capture-stdout-stderr.html
prowler_default_usage_error = "usage: prowler [-h] [-v] {aws,azure,gcp} ..."


def mock_get_available_providers():
    return ["aws", "azure", "gcp"]


class Test_Parser:
    def setup_method(self):
        # We need this to mock the get_available_providers function call
        # since the importlib.import_module is not working starting from the test class
        self.patch_get_available_providers = patch(
            "prowler.providers.common.arguments.get_available_providers",
            new=mock_get_available_providers,
        )
        self.patch_get_available_providers.start()

        # Init parser
        self.parser = ProwlerArgumentParser()

    def test_default_parser_no_arguments_aws(self):
        provider = "aws"
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert parsed.provider == provider
        assert not parsed.quiet
        assert len(parsed.output_modes) == 4
        assert "csv" in parsed.output_modes
        assert "html" in parsed.output_modes
        assert "json" in parsed.output_modes
        assert not parsed.output_filename
        assert "output" in parsed.output_directory
        assert not parsed.verbose
        assert not parsed.no_banner
        assert not parsed.slack
        assert not parsed.unix_timestamp
        assert parsed.log_level == "CRITICAL"
        assert not parsed.log_file
        assert not parsed.only_logs
        assert not parsed.checks
        assert not parsed.checks_file
        assert not parsed.checks_folder
        assert not parsed.services
        assert not parsed.severity
        assert not parsed.compliance
        assert len(parsed.categories) == 0
        assert not parsed.excluded_checks
        assert not parsed.excluded_services
        assert not parsed.list_checks
        assert not parsed.list_services
        assert not parsed.list_compliance
        assert not parsed.list_compliance_requirements
        assert not parsed.list_categories
        assert not parsed.profile
        assert not parsed.role
        assert parsed.session_duration == 3600
        assert not parsed.external_id
        assert not parsed.region
        assert not parsed.organizations_role
        assert not parsed.security_hub
        assert not parsed.quick_inventory
        assert not parsed.output_bucket
        assert not parsed.output_bucket_no_assume
        assert not parsed.shodan
        assert not parsed.allowlist_file
        assert not parsed.resource_tags
        assert not parsed.ignore_unused_services
        assert not parsed.clean_local_output_directories

    def test_default_parser_no_arguments_azure(self):
        provider = "azure"
        command = [prowler_command, provider]
        parsed = self.parser.parse(command)
        assert parsed.provider == provider
        assert not parsed.quiet
        assert len(parsed.output_modes) == 4
        assert "csv" in parsed.output_modes
        assert "html" in parsed.output_modes
        assert "json" in parsed.output_modes
        assert not parsed.output_filename
        assert "output" in parsed.output_directory
        assert not parsed.verbose
        assert not parsed.no_banner
        assert not parsed.slack
        assert not parsed.unix_timestamp
        assert parsed.log_level == "CRITICAL"
        assert not parsed.log_file
        assert not parsed.only_logs
        assert not parsed.checks
        assert not parsed.checks_file
        assert not parsed.checks_folder
        assert not parsed.services
        assert not parsed.severity
        assert not parsed.compliance
        assert len(parsed.categories) == 0
        assert not parsed.excluded_checks
        assert not parsed.excluded_services
        assert not parsed.list_checks
        assert not parsed.list_services
        assert not parsed.list_compliance
        assert not parsed.list_compliance_requirements
        assert not parsed.list_categories
        assert len(parsed.subscription_ids) == 0
        assert not parsed.az_cli_auth
        assert not parsed.sp_env_auth
        assert not parsed.browser_auth
        assert not parsed.managed_identity_auth

    def test_default_parser_no_arguments_gcp(self):
        provider = "gcp"
        command = [prowler_command, provider]
        parsed = self.parser.parse(command)
        assert parsed.provider == provider
        assert not parsed.quiet
        assert len(parsed.output_modes) == 4
        assert "csv" in parsed.output_modes
        assert "html" in parsed.output_modes
        assert "json" in parsed.output_modes
        assert not parsed.output_filename
        assert "output" in parsed.output_directory
        assert not parsed.verbose
        assert not parsed.no_banner
        assert not parsed.slack
        assert not parsed.unix_timestamp
        assert parsed.log_level == "CRITICAL"
        assert not parsed.log_file
        assert not parsed.only_logs
        assert not parsed.checks
        assert not parsed.checks_file
        assert not parsed.checks_folder
        assert not parsed.services
        assert not parsed.severity
        assert not parsed.compliance
        assert len(parsed.categories) == 0
        assert not parsed.excluded_checks
        assert not parsed.excluded_services
        assert not parsed.list_checks
        assert not parsed.list_services
        assert not parsed.list_compliance
        assert not parsed.list_compliance_requirements
        assert not parsed.list_categories
        assert not parsed.credentials_file

    def test_root_parser_version_short(self):
        command = [prowler_command, "-v"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 0

    def test_root_parser_version_long(self):
        command = [prowler_command, "--version"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 0

    def test_root_parser_help_short(self):
        command = [prowler_command, "-h"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 0

    def test_root_parser_help_long(self):
        command = [prowler_command, "--help"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 0

    def test_root_parser_default_aws_provider(self):
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert parsed.provider == "aws"

    def test_root_parser_aws_provider(self):
        command = [prowler_command, "aws"]
        parsed = self.parser.parse(command)
        assert parsed.provider == "aws"

    def test_root_parser_azure_provider(self):
        command = [prowler_command, "azure"]
        parsed = self.parser.parse(command)
        print(parsed)
        assert parsed.provider == "azure"

    def test_root_parser_gcp_provider(self):
        command = [prowler_command, "gcp"]
        parsed = self.parser.parse(command)
        print(parsed)
        assert parsed.provider == "gcp"

    def test_root_parser_quiet_short(self):
        command = [prowler_command, "-q"]
        parsed = self.parser.parse(command)
        assert parsed.quiet

    def test_root_parser_quiet_long(self):
        command = [prowler_command, "--quiet"]
        parsed = self.parser.parse(command)
        assert parsed.quiet

    def test_root_parser_exit_code_3_short(self):
        command = [prowler_command, "-z"]
        parsed = self.parser.parse(command)
        assert parsed.ignore_exit_code_3

    def test_root_parser_exit_code_3_long(self):
        command = [prowler_command, "--ignore-exit-code-3"]
        parsed = self.parser.parse(command)
        assert parsed.ignore_exit_code_3

    def test_root_parser_default_output_modes(self):
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert len(parsed.output_modes) == 4
        assert "csv" in parsed.output_modes
        assert "json" in parsed.output_modes
        assert "html" in parsed.output_modes

    def test_root_parser_output_modes_short(self):
        command = [prowler_command, "-M", "csv"]
        parsed = self.parser.parse(command)
        assert len(parsed.output_modes) == 1
        assert "csv" in parsed.output_modes

    def test_root_parser_output_modes_long(self):
        command = [prowler_command, "--output-modes", "csv"]
        parsed = self.parser.parse(command)
        assert len(parsed.output_modes) == 1
        assert "csv" in parsed.output_modes

    def test_root_parser_output_filename_short(self):
        filename = "test_output.txt"
        command = [prowler_command, "-F", filename]
        parsed = self.parser.parse(command)
        assert parsed.output_filename == filename

    def test_root_parser_output_filename_long(self):
        filename = "test_output.txt"
        command = [prowler_command, "-F", filename]
        parsed = self.parser.parse(command)
        assert parsed.output_filename == filename

    def test_root_parser_output_directory_default(self):
        dirname = "output"
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert dirname in parsed.output_directory

    def test_root_parser_output_directory_default_short(self):
        dirname = "outputs"
        command = [prowler_command, "-o", dirname]
        parsed = self.parser.parse(command)
        assert parsed.output_directory == dirname

    def test_root_parser_output_directory_default_long(self):
        dirname = "outputs"
        command = [prowler_command, "--output-directory", dirname]
        parsed = self.parser.parse(command)
        assert parsed.output_directory == dirname

    def test_root_parser_verbose(self):
        command = [prowler_command, "--verbose"]
        parsed = self.parser.parse(command)
        assert parsed.verbose

    def test_root_parser_no_banner_short(self):
        command = [prowler_command, "-b"]
        parsed = self.parser.parse(command)
        assert parsed.no_banner

    def test_root_parser_no_banner_long(self):
        command = [prowler_command, "--no-banner"]
        parsed = self.parser.parse(command)
        assert parsed.no_banner

    def test_root_parser_slack(self):
        command = [prowler_command, "--slack"]
        parsed = self.parser.parse(command)
        assert parsed.slack

    def test_root_parser_unix_timestamp(self):
        command = [prowler_command, "--unix-timestamp"]
        parsed = self.parser.parse(command)
        assert parsed.unix_timestamp

    def test_root_parser_clean_local_output_directories(self):
        command = [prowler_command, "--clean-local-output-directories"]
        parsed = self.parser.parse(command)
        assert parsed.clean_local_output_directories

    def test_logging_parser_only_logs_set(self):
        command = [prowler_command, "--only-logs"]
        parsed = self.parser.parse(command)
        assert parsed.only_logs
        assert parsed.no_banner

    def test_logging_parser_log_level_default(self):
        log_level = "CRITICAL"
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_level_debug(self):
        log_level = "DEBUG"
        command = [prowler_command, "--log-level", log_level]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_level_info(self):
        log_level = "INFO"
        command = [prowler_command, "--log-level", log_level]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_level_warning(self):
        log_level = "WARNING"
        command = [prowler_command, "--log-level", log_level]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_level_error(self):
        log_level = "ERROR"
        command = [prowler_command, "--log-level", log_level]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_level_critical(self):
        log_level = "CRITICAL"
        command = [prowler_command, "--log-level", log_level]
        parsed = self.parser.parse(command)
        assert parsed.log_level == log_level

    def test_logging_parser_log_file_default(self):
        command = [prowler_command]
        parsed = self.parser.parse(command)
        assert not parsed.log_file

    def test_logging_parser_log_file(self):
        log_file = "test.log"
        command = [prowler_command, "--log-file", log_file]
        parsed = self.parser.parse(command)
        assert parsed.log_file == log_file

    def test_exclude_checks_parser_excluded_checks_short(self):
        excluded_checks = "check_test"
        command = [prowler_command, "-e", excluded_checks]
        parsed = self.parser.parse(command)
        assert excluded_checks in parsed.excluded_checks

    def test_exclude_checks_parser_excluded_checks_short_two(self):
        excluded_checks_1 = "check_test_1"
        excluded_checks_2 = "check_test_2"
        command = [prowler_command, "-e", excluded_checks_1, excluded_checks_2]
        parsed = self.parser.parse(command)
        assert len(parsed.excluded_checks) == 2
        assert excluded_checks_1 in parsed.excluded_checks
        assert excluded_checks_2 in parsed.excluded_checks

    def test_exclude_checks_parser_excluded_checks_long(self):
        excluded_check = "check_test"
        command = [prowler_command, "--excluded-checks", excluded_check]
        parsed = self.parser.parse(command)
        assert excluded_check in parsed.excluded_checks

    def test_exclude_checks_parser_excluded_checks_long_two(self):
        excluded_checks_1 = "check_test_1"
        excluded_checks_2 = "check_test_2"
        command = [
            prowler_command,
            "--excluded-checks",
            excluded_checks_1,
            excluded_checks_2,
        ]
        parsed = self.parser.parse(command)
        assert len(parsed.excluded_checks) == 2
        assert excluded_checks_1 in parsed.excluded_checks
        assert excluded_checks_2 in parsed.excluded_checks

    def test_exclude_checks_parser_excluded_services_long(self):
        excluded_service = "accessanalyzer"
        command = [prowler_command, "--excluded-services", excluded_service]
        parsed = self.parser.parse(command)
        assert excluded_service in parsed.excluded_services

    def test_exclude_checks_parser_excluded_services_long_two(self):
        excluded_service_1 = "accessanalyzer"
        excluded_service_2 = "s3"
        command = [
            prowler_command,
            "--excluded-services",
            excluded_service_1,
            excluded_service_2,
        ]
        parsed = self.parser.parse(command)
        assert len(parsed.excluded_services) == 2
        assert excluded_service_1 in parsed.excluded_services
        assert excluded_service_2 in parsed.excluded_services

    def test_checks_parser_checks_short(self):
        check = "check_test_1"
        argument = "-c"
        command = [prowler_command, argument, check]
        parsed = self.parser.parse(command)
        assert len(parsed.checks) == 1
        assert check in parsed.checks

    def test_checks_parser_checks_short_two(self):
        check_1 = "check_test_1"
        check_2 = "check_test_2"
        argument = "-c"
        command = [prowler_command, argument, check_1, check_2]
        parsed = self.parser.parse(command)
        assert len(parsed.checks) == 2
        assert check_1 in parsed.checks
        assert check_2 in parsed.checks

    def test_checks_parser_checks_long(self):
        check = "check_test_1"
        argument = "--checks"
        command = [prowler_command, argument, check]
        parsed = self.parser.parse(command)
        assert len(parsed.checks) == 1
        assert check in parsed.checks

    def test_checks_parser_checks_long_two(self):
        check_1 = "check_test_1"
        check_2 = "check_test_2"
        argument = "--checks"
        command = [prowler_command, argument, check_1, check_2]
        parsed = self.parser.parse(command)
        assert len(parsed.checks) == 2
        assert check_1 in parsed.checks
        assert check_2 in parsed.checks

    def test_checks_parser_checks_file_short(self):
        argument = "-C"
        filename = "checks.txt"
        command = [prowler_command, argument, filename]
        parsed = self.parser.parse(command)
        assert parsed.checks_file == filename

    def test_checks_parser_checks_file_long(self):
        argument = "--checks-file"
        filename = "checks.txt"
        command = [prowler_command, argument, filename]
        parsed = self.parser.parse(command)
        assert parsed.checks_file == filename

    def test_checks_parser_checks_folder_short(self):
        argument = "-x"
        filename = "custom-checks-folder/"
        command = [prowler_command, argument, filename]
        parsed = self.parser.parse(command)
        assert parsed.checks_folder == filename

    def test_checks_parser_checks_folder_long(self):
        argument = "--checks-folder"
        filename = "custom-checks-folder/"
        command = [prowler_command, argument, filename]
        parsed = self.parser.parse(command)
        assert parsed.checks_folder == filename

    def test_checks_parser_services_short(self):
        argument = "-s"
        service_1 = "iam"
        command = [prowler_command, argument, service_1]
        parsed = self.parser.parse(command)
        assert service_1 in parsed.services

    def test_checks_parser_services_short_two(self):
        argument = "-s"
        service_1 = "iam"
        service_2 = "s3"
        command = [prowler_command, argument, service_1, service_2]
        parsed = self.parser.parse(command)
        assert len(parsed.services) == 2
        assert service_1 in parsed.services
        assert service_2 in parsed.services

    def test_checks_parser_services_long(self):
        argument = "--services"
        service_1 = "iam"
        command = [prowler_command, argument, service_1]
        parsed = self.parser.parse(command)
        assert service_1 in parsed.services

    def test_checks_parser_services_long_two(self):
        argument = "--services"
        service_1 = "iam"
        service_2 = "s3"
        command = [prowler_command, argument, service_1, service_2]
        parsed = self.parser.parse(command)
        assert len(parsed.services) == 2
        assert service_1 in parsed.services
        assert service_2 in parsed.services

    def test_checks_parser_services_with_severity(self):
        argument1 = "--services"
        service_1 = "iam"
        argument2 = "--severity"
        severity = "low"
        command = [prowler_command, argument1, service_1, argument2, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.services) == 1
        assert service_1 in parsed.services
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_informational_severity(self):
        argument = "--severity"
        severity = "informational"
        command = [prowler_command, argument, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_low_severity(self):
        argument = "--severity"
        severity = "low"
        command = [prowler_command, argument, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_medium_severity(self):
        argument = "--severity"
        severity = "medium"
        command = [prowler_command, argument, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_high_severity(self):
        argument = "--severity"
        severity = "high"
        command = [prowler_command, argument, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_critical_severity(self):
        argument = "--severity"
        severity = "critical"
        command = [prowler_command, argument, severity]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 1
        assert severity in parsed.severity

    def test_checks_parser_two_severities(self):
        argument = "--severity"
        severity_1 = "critical"
        severity_2 = "high"
        command = [prowler_command, argument, severity_1, severity_2]
        parsed = self.parser.parse(command)
        assert len(parsed.severity) == 2
        assert severity_1 in parsed.severity
        assert severity_2 in parsed.severity

    def test_checks_parser_wrong_severity(self, capsys):
        argument = "--severity"
        severity = "kk"
        command = [prowler_command, argument, severity]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_checks_parser_wrong_compliance(self):
        argument = "--compliance"
        framework = "ens_rd2022_azure"
        command = [prowler_command, argument, framework]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_checks_parser_compliance(self):
        argument = "--compliance"
        framework = "cis_1.5_aws"
        command = [prowler_command, argument, framework]
        parsed = self.parser.parse(command)
        assert len(parsed.compliance) == 1
        assert framework in parsed.compliance

    def test_checks_parser_compliance_two(self):
        argument = "--compliance"
        framework_1 = "cis_1.5_aws"
        framework_2 = "ens_rd2022_aws"
        command = [prowler_command, argument, framework_1, framework_2]
        parsed = self.parser.parse(command)
        assert len(parsed.compliance) == 2
        assert framework_1 in parsed.compliance
        assert framework_2 in parsed.compliance

    def test_checks_parser_categories(self):
        argument = "--categories"
        category = "secrets"
        command = [prowler_command, argument, category]
        parsed = self.parser.parse(command)
        assert len(parsed.categories) == 1
        assert category in parsed.categories

    def test_checks_parser_categories_two(self):
        argument = "--categories"
        category_1 = "secrets"
        category_2 = "forensics"
        command = [prowler_command, argument, category_1, category_2]
        parsed = self.parser.parse(command)
        assert len(parsed.categories) == 2
        assert category_1 in parsed.categories
        assert category_2 in parsed.categories

    def test_list_checks_parser_list_checks_short(self):
        argument = "-l"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_checks

    def test_list_checks_parser_list_checks_long(self):
        argument = "--list-checks"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_checks

    def test_list_checks_parser_list_checks_json(self):
        argument = "--list-checks-json"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_checks_json

    def test_list_checks_parser_list_services(self):
        argument = "--list-services"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_services

    def test_list_checks_parser_list_compliance(self):
        argument = "--list-compliance"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_compliance

    def test_list_checks_parser_list_categories(self):
        argument = "--list-categories"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.list_categories

    def test_list_checks_parser_list_compliance_requirements_no_arguments(self):
        argument = "--list-compliance-requirements"
        command = [prowler_command, argument]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_list_checks_parser_list_compliance_requirements_bad(self):
        argument = "--list-compliance-requirements"
        bad_framework = "cis_1.4_azure"
        command = [prowler_command, argument, bad_framework]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_list_checks_parser_list_compliance_requirements_one(self):
        argument = "--list-compliance-requirements"
        framework = "cis_1.4_aws"
        command = [prowler_command, argument, framework]
        parsed = self.parser.parse(command)
        assert len(parsed.list_compliance_requirements) == 1
        assert framework in parsed.list_compliance_requirements

    def test_aws_parser_profile_no_profile_short(self):
        argument = "-p"
        profile = ""
        command = [prowler_command, argument, profile]
        parsed = self.parser.parse(command)
        assert parsed.profile == profile

    def test_aws_parser_profile_short(self):
        argument = "-p"
        profile = "test"
        command = [prowler_command, argument, profile]
        parsed = self.parser.parse(command)
        assert parsed.profile == profile

    def test_aws_parser_profile_long(self):
        argument = "--profile"
        profile = "test"
        command = [prowler_command, argument, profile]
        parsed = self.parser.parse(command)
        assert parsed.profile == profile

    def test_aws_parser_no_role_arn_short(self):
        argument = "-R"
        role = ""
        command = [prowler_command, argument, role]
        parsed = self.parser.parse(command)
        assert parsed.role == role

    def test_aws_parser_role_arn_short(self):
        argument = "-R"
        role = "test"
        command = [prowler_command, argument, role]
        parsed = self.parser.parse(command)
        assert parsed.role == role

    def test_aws_parser_role_arn_long(self):
        argument = "--role"
        role = "test"
        command = [prowler_command, argument, role]
        parsed = self.parser.parse(command)
        assert parsed.role == role

    def test_aws_parser_mfa(self):
        argument = "--mfa"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.mfa

    def test_aws_parser_session_duration_short(self, capsys):
        argument = "-T"
        duration = "900"
        command = [prowler_command, argument, duration]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: aws: To use -I/-T options -R option is needed\n"
        )

    def test_aws_parser_session_duration_long(self, capsys):
        argument = "--session-duration"
        duration = "900"
        command = [prowler_command, argument, duration]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: aws: To use -I/-T options -R option is needed\n"
        )

    # TODO
    def test_aws_parser_external_id_no_short(self):
        argument = "-I"
        external_id = ""
        command = [prowler_command, argument, external_id]
        parsed = self.parser.parse(command)
        assert not parsed.profile

    def test_aws_parser_external_id_short(self, capsys):
        argument = "-I"
        external_id = str(uuid.uuid4())
        command = [prowler_command, argument, external_id]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: aws: To use -I/-T options -R option is needed\n"
        )

    def test_aws_parser_external_id_long(self, capsys):
        argument = "--external-id"
        external_id = str(uuid.uuid4())
        command = [prowler_command, argument, external_id]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: aws: To use -I/-T options -R option is needed\n"
        )

    def test_aws_parser_region_f(self):
        argument = "-f"
        region = "eu-west-1"
        command = [prowler_command, argument, region]
        parsed = self.parser.parse(command)
        assert len(parsed.region) == 1
        assert region in parsed.region

    def test_aws_parser_region_f_bad_region(self):
        argument = "-f"
        region = "no-region"
        command = [prowler_command, argument, region]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_aws_parser_region(self):
        argument = "--region"
        region = "eu-west-1"
        command = [prowler_command, argument, region]
        parsed = self.parser.parse(command)
        assert len(parsed.region) == 1
        assert region in parsed.region

    def test_aws_parser_two_regions(self):
        argument = "--region"
        region_1 = "eu-west-1"
        region_2 = "eu-west-2"
        command = [prowler_command, argument, region_1, region_2]
        parsed = self.parser.parse(command)
        assert len(parsed.region) == 2
        assert region_1 in parsed.region
        assert region_2 in parsed.region

    def test_aws_parser_bad_region(self):
        argument = "--region"
        region = "no-region"
        command = [prowler_command, argument, region]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_aws_parser_filter_region(self):
        argument = "--filter-region"
        region = "eu-west-1"
        command = [prowler_command, argument, region]
        parsed = self.parser.parse(command)
        assert len(parsed.region) == 1
        assert region in parsed.region

    def test_aws_parser_bad_filter_region(self):
        argument = "--filter-region"
        region = "no-region"
        command = [prowler_command, argument, region]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2

    def test_aws_parser_organizations_role_short(self):
        argument = "-O"
        organizations_role = "role_test"
        command = [prowler_command, argument, organizations_role]
        parsed = self.parser.parse(command)
        assert parsed.organizations_role == organizations_role

    def test_aws_parser_organizations_role_long(self):
        argument = "--organizations-role"
        organizations_role = "role_test"
        command = [prowler_command, argument, organizations_role]
        parsed = self.parser.parse(command)
        assert parsed.organizations_role == organizations_role

    def test_aws_parser_security_hub_short(self):
        argument = "-S"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.security_hub

    def test_aws_parser_security_hub_long(self):
        argument = "--security-hub"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.security_hub

    def test_aws_parser_skip_sh_update(self):
        argument = "--skip-sh-update"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.skip_sh_update

    def test_aws_parser_quick_inventory_short(self):
        argument = "-i"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.quick_inventory

    def test_aws_parser_quick_inventory_long(self):
        argument = "--quick-inventory"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.quick_inventory

    def test_aws_parser_output_bucket_short(self):
        argument = "-B"
        bucket = "test-bucket"
        command = [prowler_command, argument, bucket]
        parsed = self.parser.parse(command)
        assert parsed.output_bucket == bucket

    def test_aws_parser_output_bucket_long(self):
        argument = "--output-bucket"
        bucket = "test-bucket"
        command = [prowler_command, argument, bucket]
        parsed = self.parser.parse(command)
        assert parsed.output_bucket == bucket

    def test_aws_parser_output_bucket_no_assume_short(self):
        argument = "-D"
        bucket = "test-bucket"
        command = [prowler_command, argument, bucket]
        parsed = self.parser.parse(command)
        assert parsed.output_bucket_no_assume == bucket

    def test_aws_parser_output_bucket_no_assume_long(self):
        argument = "--output-bucket-no-assume"
        bucket = "test-bucket"
        command = [prowler_command, argument, bucket]
        parsed = self.parser.parse(command)
        assert parsed.output_bucket_no_assume == bucket

    def test_aws_parser_shodan_short(self):
        argument = "-N"
        shodan_api_key = str(uuid.uuid4())
        command = [prowler_command, argument, shodan_api_key]
        parsed = self.parser.parse(command)
        assert parsed.shodan == shodan_api_key

    def test_aws_parser_shodan_long(self):
        argument = "--shodan"
        shodan_api_key = str(uuid.uuid4())
        command = [prowler_command, argument, shodan_api_key]
        parsed = self.parser.parse(command)
        assert parsed.shodan == shodan_api_key

    def test_aws_parser_allowlist_short(self):
        argument = "-w"
        allowlist_file = "allowlist.txt"
        command = [prowler_command, argument, allowlist_file]
        parsed = self.parser.parse(command)
        assert parsed.allowlist_file == allowlist_file

    def test_aws_parser_allowlist_long(self):
        argument = "--allowlist-file"
        allowlist_file = "allowlist.txt"
        command = [prowler_command, argument, allowlist_file]
        parsed = self.parser.parse(command)
        assert parsed.allowlist_file == allowlist_file

    def test_aws_parser_resource_tags(self):
        argument = "--resource-tags"
        scan_tag1 = "Key=Value"
        scan_tag2 = "Key2=Value2"
        command = [prowler_command, argument, scan_tag1, scan_tag2]
        parsed = self.parser.parse(command)
        assert len(parsed.resource_tags) == 2
        assert scan_tag1 in parsed.resource_tags
        assert scan_tag2 in parsed.resource_tags

    def test_aws_parser_resource_arn(self):
        argument = "--resource-arn"
        resource_arn1 = "arn:aws:iam::012345678910:user/test"
        resource_arn2 = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678"
        command = [prowler_command, argument, resource_arn1, resource_arn2]
        parsed = self.parser.parse(command)
        assert len(parsed.resource_arn) == 2
        assert resource_arn1 in parsed.resource_arn
        assert resource_arn2 in parsed.resource_arn

    def test_aws_parser_wrong_resource_arn(self):
        argument = "--resource-arn"
        resource_arn = "arn:azure:iam::account:user/test"
        command = [prowler_command, argument, resource_arn]
        with pytest.raises(SystemExit) as ex:
            self.parser.parse(command)
        assert ex.type == SystemExit

    def test_aws_parser_aws_retries_max_attempts(self):
        argument = "--aws-retries-max-attempts"
        max_retries = "10"
        command = [prowler_command, argument, max_retries]
        parsed = self.parser.parse(command)
        assert parsed.aws_retries_max_attempts == int(max_retries)

    def test_aws_parser_ignore_unused_services(self):
        argument = "--ignore-unused-services"
        command = [prowler_command, argument]
        parsed = self.parser.parse(command)
        assert parsed.ignore_unused_services

    def test_aws_parser_config_file(self):
        argument = "--config-file"
        config_file = "./test-config.yaml"
        command = [prowler_command, argument, config_file]
        parsed = self.parser.parse(command)
        assert parsed.config_file == config_file

    def test_aws_parser_sts_endpoint_region(self):
        argument = "--sts-endpoint-region"
        sts_endpoint_region = "eu-west-1"
        command = [prowler_command, argument, sts_endpoint_region]
        parsed = self.parser.parse(command)
        assert parsed.sts_endpoint_region == sts_endpoint_region

    def test_parser_azure_auth_sp(self):
        argument = "--sp-env-auth"
        command = [prowler_command, "azure", argument]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.sp_env_auth

    def test_parser_azure_auth_browser(self):
        argument = "--browser-auth"
        command = [prowler_command, "azure", argument]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.browser_auth

    def test_parser_azure_tenant_id(self):
        argument = "--tenant-id"
        tenant_id = "test-tenant-id"
        command = [prowler_command, "azure", argument, tenant_id]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.tenant_id == tenant_id

    def test_parser_azure_auth_az_cli(self):
        argument = "--az-cli-auth"
        command = [prowler_command, "azure", argument]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.az_cli_auth

    def test_parser_azure_auth_managed_identity(self):
        argument = "--managed-identity-auth"
        command = [prowler_command, "azure", argument]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.managed_identity_auth

    def test_parser_azure_subscription_ids(self):
        argument = "--subscription-ids"
        subscription_1 = "test_subscription_1"
        subscription_2 = "test_subscription_2"
        command = [prowler_command, "azure", argument, subscription_1, subscription_2]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert len(parsed.subscription_ids) == 2
        assert parsed.subscription_ids[0] == subscription_1
        assert parsed.subscription_ids[1] == subscription_2

    def test_parser_azure_region(self):
        argument = "--azure-region"
        region = "AzureChinaCloud"
        command = [prowler_command, "azure", argument, region]
        parsed = self.parser.parse(command)
        assert parsed.provider == "azure"
        assert parsed.azure_region == region

    # Test AWS flags with Azure provider
    def test_parser_azure_with_aws_flag(self, capsys):
        command = [prowler_command, "azure", "-p"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: unrecognized arguments: -p\n"
        )

    # Test Azure flags with AWS provider
    def test_parser_aws_with_azure_flag(self, capsys):
        command = [prowler_command, "aws", "--subscription-ids"]
        with pytest.raises(SystemExit) as wrapped_exit:
            _ = self.parser.parse(command)
        assert wrapped_exit.type == SystemExit
        assert wrapped_exit.value.code == 2
        assert (
            capsys.readouterr().err
            == f"{prowler_default_usage_error}\nprowler: error: unrecognized arguments: --subscription-ids\n"
        )

    def test_parser_gcp_auth_credentials_file(self):
        argument = "--credentials-file"
        file = "test.json"
        command = [prowler_command, "gcp", argument, file]
        parsed = self.parser.parse(command)
        assert parsed.provider == "gcp"
        assert parsed.credentials_file == file

    def test_parser_gcp_project_ids(self):
        argument = "--project-ids"
        project_1 = "test_project_1"
        project_2 = "test_project_2"
        command = [prowler_command, "gcp", argument, project_1, project_2]
        parsed = self.parser.parse(command)
        assert parsed.provider == "gcp"
        assert len(parsed.project_ids) == 2
        assert parsed.project_ids[0] == project_1
        assert parsed.project_ids[1] == project_2

    def test_validate_azure_region_valid_regions(self):
        expected_regions = [
            "AzureChinaCloud",
            "AzureUSGovernment",
            "AzureGermanCloud",
            "AzureCloud",
        ]
        input_regions = [
            "AzureChinaCloud",
            "AzureUSGovernment",
            "AzureGermanCloud",
            "AzureCloud",
        ]
        for region in input_regions:
            assert validate_azure_region(region) in expected_regions

    def test_validate_azure_region_invalid_regions(self):
        expected_regions = [
            "AzureChinaCloud",
            "AzureUSGovernment",
            "AzureGermanCloud",
            "AzureCloud",
        ]
        invalid_region = "non-valid-region"
        with pytest.raises(
            ArgumentTypeError,
            match=f"Region {invalid_region} not allowed, allowed regions are {' '.join(expected_regions)}",
        ):
            validate_azure_region(invalid_region)
