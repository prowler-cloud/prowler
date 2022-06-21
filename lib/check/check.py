import importlib
import pkgutil
from types import ModuleType
from typing import Any

from colorama import Fore, Style

from config.config import groups_file
from lib.logger import logger
from lib.outputs import report
from lib.utils.utils import open_file, parse_json_file


# Exclude checks to run
def exclude_checks_to_run(checks_to_execute: set, excluded_checks: list) -> set:
    for check in excluded_checks:
        checks_to_execute.discard(check)
    return checks_to_execute


# Exclude groups to run
def exclude_groups_to_run(
    checks_to_execute: set, excluded_groups: list, provider: str
) -> set:
    # Recover checks from the input groups
    available_groups = parse_groups_from_file(groups_file)
    checks_from_groups = load_checks_to_execute_from_groups(
        available_groups, excluded_groups, provider
    )
    for check_name in checks_from_groups:
        checks_to_execute.discard(check_name)
    return checks_to_execute


def exclude_services_to_run(
    checks_to_execute: set, excluded_services: list, provider: str
) -> set:
    # Recover checks from the input services
    for service in excluded_services:
        modules = recover_modules_from_provider(provider, service)
        if not modules:
            logger.error(f"Service '{service}' was not found for the AWS provider")
        else:
            for check_module in modules:
                # Recover check name and module name from import path
                # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_name = check_module.split(".")[-1]
                # Exclude checks from the input services
                checks_to_execute.discard(check_name)
    return checks_to_execute


# Load checks from checklist.json
def parse_checks_from_file(input_file: str, provider: str) -> set:
    checks_to_execute = set()
    f = open_file(input_file)
    json_file = parse_json_file(f)

    for check_name in json_file[provider]:
        checks_to_execute.add(check_name)

    return checks_to_execute


# List available groups
def list_groups(provider: str) -> list:
    groups = parse_groups_from_file(groups_file)
    print(f"Available Groups:")

    for group, value in groups[provider].items():
        group_description = value["description"]
        print(f"\t - {group_description} -- [{group}] ")


# Parse groups from groups.json
def parse_groups_from_file(group_file: str) -> Any:
    f = open_file(group_file)
    available_groups = parse_json_file(f)
    return available_groups


# Parse checks from groups to execute
def load_checks_to_execute_from_groups(
    available_groups: Any, group_list: list, provider: str
) -> set:
    checks_to_execute = set()

    for group in group_list:
        if group in available_groups[provider]:
            for check_name in available_groups[provider][group]["checks"]:
                checks_to_execute.add(check_name)
        else:
            logger.error(
                f"Group '{group}' was not found for the {provider.upper()} provider"
            )
    return checks_to_execute


# Generate the list of checks to execute
def load_checks_to_execute(
    checks_file: str,
    check_list: list,
    service_list: list,
    group_list: list,
    provider: str,
) -> set:

    checks_to_execute = set()

    # Handle if there are checks passed using -c/--checks
    if check_list:
        for check_name in check_list:
            checks_to_execute.add(check_name)

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
            modules = recover_modules_from_provider(provider, service)
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
            modules = recover_modules_from_provider(provider)
        except Exception as e:
            logger.error(f"{e.__class__.__name__} -- {e}")
        else:
            for check_module in modules:
                # Recover check name from import path (last part)
                # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_name = check_module.split(".")[-1]
                checks_to_execute.add(check_name)

    return checks_to_execute


def recover_modules_from_provider(provider: str, service: str = None) -> list:
    modules = []
    module_path = f"providers.{provider}.services"
    if service:
        module_path += f".{service}"

    for module_name in pkgutil.walk_packages(
        importlib.import_module(module_path).__path__,
        importlib.import_module(module_path).__name__ + ".",
    ):
        # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
        if module_name.name.count(".") == 5:
            modules.append(module_name.name)
    return modules


def set_output_options(quiet):
    global output_options
    output_options = Output_From_Options(
        is_quiet=quiet
        # set input options here
    )
    return output_options


def run_check(check):
    print(
        f"\nCheck Name: {check.checkName} - {Fore.MAGENTA}{check.serviceName}{Fore.YELLOW}[{check.severity}]{Style.RESET_ALL}"
    )
    logger.debug(f"Executing check: {check.checkName}")
    findings = check.execute()
    report(findings, output_options)


def import_check(check_path: str) -> ModuleType:
    lib = importlib.import_module(f"{check_path}")
    return lib
