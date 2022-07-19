from config.config import groups_file
from lib.check.check import (
    load_checks_to_execute_from_groups,
    parse_checks_from_file,
    parse_groups_from_file,
    recover_checks_from_provider,
)
from lib.logger import logger


#  Generate the list of checks to execute
# test this function
def load_checks_to_execute(
    bulk_checks_metadata: dict,
    checks_file: str,
    check_list: list,
    service_list: list,
    group_list: list,
    severities: list,
    provider: str,
) -> set:

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
            logger.error(f"{e.__class__.__name__} -- {e}")

    # Handle if there are services passed using -s/--services
    elif service_list:
        # Loaded dynamically from modules within provider/services
        for service in service_list:
            modules = recover_checks_from_provider(provider, service)
            if not modules:
                logger.error(f"Service '{service}' was not found for the AWS provider")
            else:
                for check_module in modules:
                    # Recover check name and module name from import path
                    # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                    check_name = check_module.split(".")[-1]
                    # If the service is present in the group list passed as parameters
                    # if service_name in group_list: checks_to_execute.add(check_name)
                    checks_to_execute.add(check_name)

    # Handle if there are groups passed using -g/--groups
    elif group_list:
        try:
            available_groups = parse_groups_from_file(groups_file)
            checks_to_execute = load_checks_to_execute_from_groups(
                available_groups, group_list, provider
            )
        except Exception as e:
            logger.error(f"{e.__class__.__name__} -- {e}")

    # If there are no checks passed as argument
    else:
        try:
            # Get all check modules to run with the specific provider
            checks = recover_checks_from_provider(provider)
        except Exception as e:
            logger.error(f"{e.__class__.__name__} -- {e}")
        else:
            for check_name in checks:
                # Recover check name from import path (last part)
                # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_name = check_name.split(".")[-1]
                checks_to_execute.add(check_name)

    return checks_to_execute
