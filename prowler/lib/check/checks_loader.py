from prowler.lib.check.check import (
    parse_checks_from_compliance_framework,
    parse_checks_from_file,
    recover_checks_from_provider,
    recover_checks_from_service,
)
from prowler.lib.logger import logger


# Generate the list of checks to execute
# PENDING Test for this function
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
    """Generate the list of checks to execute based on the cloud provider and input arguments specified"""
    checks_to_execute = set()

    # Handle if there are checks passed using -c/--checks
    if check_list:
        for check_name in check_list:
            checks_to_execute.add(check_name)

    # Handle if there are some severities passed using --severity
    elif severities:
        for check in bulk_checks_metadata:
            # Check check's severity
            if bulk_checks_metadata[check].Severity in severities:
                checks_to_execute.add(check)

    # Handle if there are checks passed using -C/--checks-file
    elif checks_file:
        try:
            checks_to_execute = parse_checks_from_file(checks_file, provider)
        except Exception as e:
            logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")

    # Handle if there are services passed using -s/--services
    elif service_list:
        checks_to_execute = recover_checks_from_service(service_list, provider)

    # Handle if there are compliance frameworks passed using --compliance
    elif compliance_frameworks:
        try:
            checks_to_execute = parse_checks_from_compliance_framework(
                compliance_frameworks, bulk_compliance_frameworks
            )
        except Exception as e:
            logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")

    # Handle if there are categories passed using --categories
    elif categories:
        for cat in categories:
            for check in bulk_checks_metadata:
                # Check check's categories
                if cat in bulk_checks_metadata[check].Categories:
                    checks_to_execute.add(check)

    # If there are no checks passed as argument
    else:
        try:
            # Get all check modules to run with the specific provider
            checks = recover_checks_from_provider(provider)
        except Exception as e:
            logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")
        else:
            for check_info in checks:
                # Recover check name from import path (last part)
                # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_name = check_info[0]
                checks_to_execute.add(check_name)

    # Verify if any input check is an alias of another check
    for input_check in checks_to_execute:
        for check, metadata in bulk_checks_metadata.items():
            if input_check in metadata.CheckAlias:
                # Remove input check name and add the real one
                checks_to_execute.remove(input_check)
                checks_to_execute.add(check)

    return checks_to_execute
