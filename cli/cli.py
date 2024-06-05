from typing import List

import typer

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
from prowler.lib.logger import logger, logging_levels, set_logging_config

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
    provider: str = typer.Argument(..., help="The provider to check"),
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
):
    check_provider(provider)
    if list_services_bool:
        services = list_services(provider)
        print_services(services)
    if list_fixers_bool:
        fixers = list_fixers(provider)
        print_fixers(fixers)
    if list_categories_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        categories = list_categories(checks_metadata)
        print_categories(categories)
    if list_compliance_bool:
        compliance_frameworks = bulk_load_compliance_frameworks(provider)
        print_compliance_frameworks(compliance_frameworks)
    if list_compliance_requirements_value:
        valid_compliance = check_compliance_framework(
            provider, list_compliance_requirements_value
        )
        print_compliance_requirements(
            bulk_load_compliance_frameworks(provider),
            valid_compliance,
        )
    if list_checks_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        checks = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(provider),
            None,
            [],
            [],
            [],
            [],
            [],
            provider,
        )
        print_checks(provider, sorted(checks), checks_metadata)
    if list_checks_json_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        checks_to_execute = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(provider),
            None,
            [],
            [],
            [],
            [],
            [],
            provider,
        )
        print(list_checks_json(provider, sorted(checks_to_execute)))
    if log_level:
        set_logging_config(validate_log_level(log_level))
        logger.info(f"Log level set to {log_level}")
    if log_file:
        if log_level:
            set_logging_config(validate_log_level(log_level), log_file)
        else:
            set_logging_config("INFO", log_file)
        logger.info(f"Log file set to {log_file}")
    if only_logs:
        if log_level:
            set_logging_config(validate_log_level(log_level), only_logs=True)
        else:
            set_logging_config("INFO", only_logs=True)
        logger.info("Only logs are shown")
    if status_value:
        logger.info(f"Filtering by status: {status_value}")
        # TODO: Implement filtering by status in a class
    if output_formats_value:
        logger.info(f"Output formats: {output_formats_value}")
        # TODO: Implement output formats in a class
    if output_filename_value:
        logger.info(f"Output filename: {output_filename_value}")
    # TODO: Implement output filename in a class
    if output_directory_value:
        logger.info(f"Output directory: {output_directory_value}")
        # TODO: Implement output directory in a class
    if verbose:
        logger.info("Verbose output is enabled")
    if ignore_exit_code_3:
        logger.info("Ignoring exit code 3")
    if no_banner:
        logger.info("No banner is shown")
    if unix_timestamp:
        logger.info("Using Unix timestamp")


if __name__ == "__main__":
    app()
