from argparse import Namespace
from typing import List

import typer
from lib.options import OptionsState

from prowler.config.config import available_compliance_frameworks, finding_statuses
from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    list_categories,
    list_checks_json,
    list_fixers,
    list_services,
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_fixers,
    print_services,
)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.logger import logger, logging_levels, set_logging_config
from prowler.lib.outputs.security_hub.security_hub import SecurityHub
from prowler.lib.scan.scan import Scan
from prowler.providers.common.provider import Provider

app = typer.Typer()


def check_provider(provider: str):
    if provider not in ["aws", "azure", "gcp", "kubernetes"]:
        raise typer.BadParameter(
            "Invalid provider. Choose between aws, azure, gcp or kubernetes."
        )


def check_compliance_framework(provider: str, compliance_framework: list):
    # From the available_compliance_frameworks, check if the compliance_framework is valid for the provider
    compliance_frameworks_provider = []
    valid_compliance_frameworks = []
    for provider_compliance_framework in available_compliance_frameworks:
        if provider in provider_compliance_framework:
            compliance_frameworks_provider.append(provider_compliance_framework)
    for compliance in compliance_framework:
        if compliance not in compliance_frameworks_provider:
            print(f"{compliance} is not a valid Compliance Framework\n")
        else:
            valid_compliance_frameworks.append(compliance)
    return valid_compliance_frameworks


def validate_log_level(log_level: str):
    log_levels = list(logging_levels.keys())
    if log_level not in log_levels:
        raise typer.BadParameter(f"Log level must be one of {log_levels}")
    return log_level


def split_space_separated_values(value: str) -> List[str]:
    output = []
    for item in value:
        for input in item.split(" "):
            output.append(input)
    return output


def validate_status(status: str):
    if status not in finding_statuses:
        raise typer.BadParameter(f"Status must be one of {finding_statuses}")
    return status


def validate_output_formats(output_formats: List[str]):
    valid_output_formats = ["csv", "json-ocsf", "html", "json-asff"]
    for output_format in output_formats:
        if output_format not in valid_output_formats:
            raise typer.BadParameter(
                f"Output format must be one of {valid_output_formats}"
            )
    return output_formats


@app.command()
def main(
    provider: str = typer.Argument(
        ..., help="The provider to check", callback=check_provider
    ),
    list_services_bool: bool = typer.Option(
        False, "--list-services", help="List the services of the provider"
    ),
    list_fixers_bool: bool = typer.Option(
        False, "--list-fixers", help="List the fixers of the provider"
    ),
    list_categories_bool: bool = typer.Option(
        False, "--list-categories", help="List the categories of the provider"
    ),
    list_compliance_bool: bool = typer.Option(
        False,
        "--list-compliance",
        help="List the compliance frameworks of the provider",
    ),
    list_compliance_requirements_value: List[str] = typer.Option(
        None,
        "--list-compliance-requirements",
        help="List the compliance requirements of the provider",
        callback=split_space_separated_values,
    ),
    list_checks_bool: bool = typer.Option(
        False, "--list-checks", help="List the checks of the provider"
    ),
    list_checks_json_bool: bool = typer.Option(
        False,
        "--list-checks-json",
        help="List the checks of the provider in JSON format",
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Set the Log level"),
    log_file: str = typer.Option(None, "--log-file", help="Set the Log file"),
    only_logs: bool = typer.Option(False, "--only-logs", help="Only show logs"),
    status_value: str = typer.Option(
        None,
        "--status",
        help=f"Filter by the status of the findings {finding_statuses}",
        callback=validate_status,
    ),
    output_formats_value: str = typer.Option(
        "csv json-ocsf html",
        "--output-formats",
        help="Output format for the findings",
        callback=split_space_separated_values,
    ),
    output_filename_value: str = typer.Option(
        None, "--output-filename", help="Output filename"
    ),
    output_directory_value: str = typer.Option(
        None, "--output-directory", help="Output directory"
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose output"),
    ignore_exit_code_3: bool = typer.Option(
        False, "--ignore-exit-code-3", help="Ignore exit code 3"
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Do not show the banner"),
    unix_timestamp: bool = typer.Option(
        False, "--unix-timestamp", help="Use Unix timestamp"
    ),
    profile: str = typer.Option(None, "--profile", help="The profile to use"),
):
    options = OptionsState(
        provider,
        list_services_bool,
        list_fixers_bool,
        list_categories_bool,
        list_compliance_bool,
        list_compliance_requirements_value,
        list_checks_bool,
        list_checks_json_bool,
        log_level,
        log_file,
        only_logs,
        status_value,
        output_formats_value,
        output_filename_value,
        output_directory_value,
        verbose,
        ignore_exit_code_3,
        no_banner,
        unix_timestamp,
        profile,
    )

    if options.list_services:
        services = list_services(options.provider)
        print_services(services)
    if options.list_fixers:
        fixers = list_fixers(options.provider)
        print_fixers(fixers)
    if options.list_categories:
        checks_metadata = bulk_load_checks_metadata(options.provider)
        categories = list_categories(checks_metadata)
        print_categories(categories)
    if options.list_compliance:
        compliance_frameworks = bulk_load_compliance_frameworks(options.provider)
        print_compliance_frameworks(compliance_frameworks)
    if options.list_compliance_requirements:
        valid_compliance = check_compliance_framework(
            options.provider, options.list_compliance_requirements
        )
        print_compliance_requirements(
            bulk_load_compliance_frameworks(options.provider),
            valid_compliance,
        )
    if options.list_checks:
        checks_metadata = bulk_load_checks_metadata(options.provider)
        checks = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(options.provider),
            None,
            [],
            [],
            [],
            [],
            [],
            options.provider,
        )
        print_checks(options.provider, sorted(checks), checks_metadata)
    if options.list_checks_json:
        checks_metadata = bulk_load_checks_metadata(options.provider)
        checks_to_execute = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(options.provider),
            None,
            [],
            [],
            [],
            [],
            [],
            options.provider,
        )
        print(list_checks_json(options.provider, sorted(checks_to_execute)))
    if options.log_level:
        set_logging_config(validate_log_level(options.log_level))
        logger.info(f"Log level set to {options.log_level}")
    if options.log_file:
        if options.log_level:
            set_logging_config(validate_log_level(options.log_level), options.log_file)
        else:
            set_logging_config("INFO", options.log_file)
        logger.info(f"Log file set to {options.log_file}")
    if options.only_logs:
        if options.log_level:
            set_logging_config(validate_log_level(options.log_level), only_logs=True)
        else:
            set_logging_config("INFO", only_logs=True)
        logger.info("Only logs are shown")
    if options.status:
        logger.info(f"Filtering by status: {options.status}")
        # TODO: Implement filtering by status in a class
    if options.output_formats:
        logger.info(f"Output formats: {options.output_formats}")
        # TODO: Implement output formats in a class
    if options.output_filename:
        logger.info(f"Output filename: {options.output_filename}")
    # TODO: Implement output filename in a class
    if options.output_directory:
        logger.info(f"Output directory: {options.output_directory}")
    # TODO: Implement output directory in a class
    if options.verbose:
        logger.info("Verbose output is enabled")
    if options.ignore_exit_code_3:
        logger.info("Ignoring exit code 3")
    if options.no_banner:
        logger.info("No banner is shown")
    if options.unix_timestamp:
        logger.info("Using Unix timestamp")
    if options.profile:
        # Execute Prowler
        checks_to_execute = ["s3_account_level_public_access_blocks"]
        # Create the provider
        args = Namespace
        args.provider = provider
        args.profile = profile
        args.verbose = False
        args.fixer = False
        args.only_logs = False
        args.status = []
        args.output_formats = []
        args.output_filename = None
        args.unix_timestamp = False
        args.output_directory = None
        args.shodan = None
        args.security_hub = False
        args.send_sh_only_fails = False
        # args.region = ("eu-west-1")
        Provider.set_global_provider(args)
        provider = Provider.get_global_provider()
        bulk_checks_metadata = bulk_load_checks_metadata(provider.type)
        bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider.type)
        bulk_checks_metadata = update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )
        provider.output_options = (args, bulk_checks_metadata)
        provider.output_options.bulk_checks_metadata = bulk_checks_metadata
        scan = Scan(provider, checks_to_execute)
        custom_checks_metadata = None
        scan_results = scan.scan(custom_checks_metadata)
        # Verify where AWS Security Hub is enabled
        aws_security_enabled_regions = []
        security_hub_regions = (
            provider.get_available_aws_service_regions("securityhub")
            if not provider.identity.audited_regions
            else provider.identity.audited_regions
        )
        security_hub = SecurityHub(provider)
        for region in security_hub_regions:
            # Save the regions where AWS Security Hub is enabled
            if security_hub.verify_security_hub_integration_enabled_per_region(
                region,
            ):
                aws_security_enabled_regions.append(region)
        # Prepare the findings to be sent to Security Hub
        security_hub_findings_per_region = security_hub.prepare_security_hub_findings(
            scan_results,
            aws_security_enabled_regions,
        )
        # Send the findings to Security Hub
        findings_sent_to_security_hub = security_hub.batch_send_to_security_hub(
            security_hub_findings_per_region
        )
        print(findings_sent_to_security_hub)


if __name__ == "__main__":
    app()
