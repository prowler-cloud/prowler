from colorama import Fore, Style

from prowler.config.config import valid_severities
from prowler.lib.check.check import (
    parse_checks_from_compliance_framework,
    parse_checks_from_file,
    recover_checks_from_provider,
    recover_checks_from_service,
)
from prowler.lib.logger import logger


# Generate the list of checks to execute
def load_checks_to_execute(
    bulk_checks_metadata: dict,
    bulk_compliance_frameworks: dict,
    checks_file: str,
    check_list: list,
    service_list: list,
    severities: list,
    compliance_frameworks: list,
    categories: set,
    provider: str,
) -> set:
    """Generate the list of checks to execute based on the cloud provider and the input arguments given"""
    try:
        # Local subsets
        checks_to_execute = set()
        check_aliases = {}
        check_severities = {key: [] for key in valid_severities}
        check_categories = {}

        # First, loop over the bulk_checks_metadata to extract the needed subsets
        for check, metadata in bulk_checks_metadata.items():
            # Aliases
            for alias in metadata.CheckAliases:
                check_aliases[alias] = check

            # Severities
            if metadata.Severity:
                check_severities[metadata.Severity].append(check)

            # Categories
            for category in metadata.Categories:
                if category not in check_categories:
                    check_categories[category] = []
                check_categories[category].append(check)

        # Handle if there are checks passed using -c/--checks
        if check_list:
            for check_name in check_list:
                checks_to_execute.add(check_name)

        # Handle if there are some severities passed using --severity
        elif severities:
            for severity in severities:
                checks_to_execute.update(check_severities[severity])

            if service_list:
                checks_to_execute = (
                    recover_checks_from_service(service_list, provider)
                    & checks_to_execute
                )

        # Handle if there are checks passed using -C/--checks-file
        elif checks_file:
            checks_to_execute = parse_checks_from_file(checks_file, provider)

        # Handle if there are services passed using -s/--services
        elif service_list:
            checks_to_execute = recover_checks_from_service(service_list, provider)

        # Handle if there are compliance frameworks passed using --compliance
        elif compliance_frameworks:
            checks_to_execute = parse_checks_from_compliance_framework(
                compliance_frameworks, bulk_compliance_frameworks
            )

        # Handle if there are categories passed using --categories
        elif categories:
            for category in categories:
                checks_to_execute.update(check_categories[category])

        # If there are no checks passed as argument
        else:
            # Get all check modules to run with the specific provider
            checks = recover_checks_from_provider(provider)

            for check_info in checks:
                # Recover check name from import path (last part)
                # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_name = check_info[0]
                checks_to_execute.add(check_name)

        # Check Aliases
        checks_to_execute = update_checks_to_execute_with_aliases(
            checks_to_execute, check_aliases
        )

        return checks_to_execute

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )


def update_checks_to_execute_with_aliases(
    checks_to_execute: set, check_aliases: dict
) -> set:
    """update_checks_to_execute_with_aliases returns the checks_to_execute updated using the check aliases."""
    # Verify if any input check is an alias of another check
    for input_check in checks_to_execute:
        if (
            input_check in check_aliases
            and check_aliases[input_check] not in checks_to_execute
        ):
            # Remove input check name and add the real one
            checks_to_execute.remove(input_check)
            checks_to_execute.add(check_aliases[input_check])
            print(
                f"\nUsing alias {Fore.YELLOW}{input_check}{Style.RESET_ALL} for check {Fore.YELLOW}{check_aliases[input_check]}{Style.RESET_ALL}...\n"
            )
    return checks_to_execute
