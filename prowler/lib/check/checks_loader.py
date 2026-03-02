import sys

from colorama import Fore, Style

from prowler.lib.check.check import parse_checks_from_file
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata, Severity
from prowler.lib.logger import logger


# Generate the list of checks to execute
def load_checks_to_execute(
    provider: str,
    bulk_checks_metadata: dict = None,
    bulk_compliance_frameworks: dict = None,
    checks_file: str = None,
    check_list: list = None,
    service_list: list = None,
    severities: list = None,
    compliance_frameworks: list = None,
    categories: set = None,
) -> set:
    """Generate the list of checks to execute based on the cloud provider and the input arguments given"""
    try:
        # Bypass check loading for providers that use Trivy directly
        if provider in ("iac", "image"):
            return set()

        # Local subsets
        checks_to_execute = set()
        check_aliases = {}
        check_categories = {}
        check_severities = {severity.value: [] for severity in Severity}

        if not bulk_checks_metadata:
            bulk_checks_metadata = CheckMetadata.get_bulk(provider=provider)
        # First, loop over the bulk_checks_metadata to extract the needed subsets
        for check, metadata in bulk_checks_metadata.items():
            try:
                # Aliases
                for alias in metadata.CheckAliases:
                    if alias not in check_aliases:
                        check_aliases[alias] = []
                    check_aliases[alias].append(check)

                # Severities
                if metadata.Severity:
                    check_severities[metadata.Severity].append(check)

                # Categories
                for category in metadata.Categories:
                    if category not in check_categories:
                        check_categories[category] = []
                    check_categories[category].append(check)
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )

        # Handle if there are checks passed using -c/--checks
        if check_list:
            # Validate that all checks exist
            available_checks = set(bulk_checks_metadata.keys())
            available_checks.update(check_aliases.keys())
            invalid_checks = []
            for check_name in check_list:
                if check_name not in available_checks:
                    invalid_checks.append(check_name)
                else:
                    checks_to_execute.add(check_name)

            if invalid_checks:
                logger.critical(
                    f"Invalid check(s) specified: {', '.join(invalid_checks)}"
                )
                logger.critical(
                    f"Please provide valid check names. Use 'prowler {provider} --list-checks' to see available checks."
                )
                sys.exit(1)

        # Handle if there are some severities passed using --severity
        elif severities:
            for severity in severities:
                checks_to_execute.update(check_severities[severity])

            if service_list:
                # Validate that all services exist
                available_services = set()
                for metadata in bulk_checks_metadata.values():
                    available_services.add(metadata.ServiceName)

                invalid_services = [
                    s for s in service_list if s not in available_services
                ]
                if invalid_services:
                    logger.critical(
                        f"Invalid service(s) specified: {', '.join(invalid_services)}"
                    )
                    logger.critical(
                        f"Please provide valid service names. Use 'prowler {provider} --list-services' to see available services."
                    )
                    sys.exit(1)

                checks_from_services = set()
                for service in service_list:
                    service_checks = CheckMetadata.list(
                        bulk_checks_metadata=bulk_checks_metadata,
                        service=service,
                    )
                    checks_from_services.update(service_checks)
                checks_to_execute = checks_from_services & checks_to_execute

        # Handle if there are checks passed using -C/--checks-file
        elif checks_file:
            checks_to_execute = parse_checks_from_file(checks_file, provider)

        # Handle if there are services passed using -s/--services
        elif service_list:
            # Validate that all services exist
            available_services = set()
            for metadata in bulk_checks_metadata.values():
                available_services.add(metadata.ServiceName)

            invalid_services = [s for s in service_list if s not in available_services]
            if invalid_services:
                logger.critical(
                    f"Invalid service(s) specified: {', '.join(invalid_services)}"
                )
                logger.critical(
                    f"Please provide valid service names. Use 'prowler {provider} --list-services' to see available services."
                )
                sys.exit(1)

            for service in service_list:
                checks_to_execute.update(
                    CheckMetadata.list(
                        bulk_checks_metadata=bulk_checks_metadata,
                        service=service,
                    )
                )

        # Handle if there are compliance frameworks passed using --compliance
        elif compliance_frameworks:
            if not bulk_compliance_frameworks:
                bulk_compliance_frameworks = Compliance.get_bulk(provider=provider)
            for compliance_framework in compliance_frameworks:
                checks_to_execute.update(
                    CheckMetadata.list(
                        bulk_compliance_frameworks=bulk_compliance_frameworks,
                        compliance_framework=compliance_framework,
                    )
                )

        # Handle if there are categories passed using --categories
        elif categories:
            # Validate that all categories exist
            available_categories = set(check_categories.keys())
            invalid_categories = [
                c for c in categories if c not in available_categories
            ]
            if invalid_categories:
                logger.critical(
                    f"Invalid category(ies) specified: {', '.join(invalid_categories)}"
                )
                logger.critical(
                    f"Please provide valid category names. Use 'prowler {provider} --list-categories' to see available categories."
                )
                sys.exit(1)

            for category in categories:
                checks_to_execute.update(check_categories[category])

        # If there are no checks passed as argument
        else:
            # get all checks
            for check_name in CheckMetadata.list(
                bulk_checks_metadata=bulk_checks_metadata
            ):
                checks_to_execute.add(check_name)
        # Only execute threat detection checks if threat-detection category is set
        if (not categories or "threat-detection" not in categories) and not check_list:
            for threat_detection_check in check_categories.get("threat-detection", []):
                checks_to_execute.discard(threat_detection_check)

        # Check Aliases
        checks_to_execute = update_checks_to_execute_with_aliases(
            checks_to_execute, check_aliases
        )

        return checks_to_execute

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        return checks_to_execute


def update_checks_to_execute_with_aliases(
    checks_to_execute: set, check_aliases: dict
) -> set:
    """update_checks_to_execute_with_aliases returns the checks_to_execute updated using the check aliases."""
    # Verify if any input check is an alias of another check
    try:
        new_checks_to_execute = checks_to_execute.copy()
        for input_check in checks_to_execute:
            if input_check in check_aliases:
                # Remove input check name and add the real one
                new_checks_to_execute.remove(input_check)
                for alias in check_aliases[input_check]:
                    if alias not in new_checks_to_execute:
                        new_checks_to_execute.add(alias)
                        print(
                            f"\nUsing alias {Fore.YELLOW}{input_check}{Style.RESET_ALL} for check {Fore.YELLOW}{alias}{Style.RESET_ALL}..."
                        )
        return new_checks_to_execute
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
