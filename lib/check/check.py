import importlib
from pkgutil import walk_packages
from types import ModuleType
from typing import Any

# import time
from colorama import Fore, Style

from config.config import groups_file
from lib.check.models import Output_From_Options, load_check_metadata
from lib.logger import logger
from lib.outputs import report
from lib.utils.utils import open_file, parse_json_file


# Load all checks metadata
def bulk_load_checks_metadata(provider: str) -> dict:
    bulk_check_metadata = {}
    checks = recover_checks_from_provider(provider)
    # Build list of check's metadata files
    for check_name in checks:
        # Build check path name
        check_path_name = check_name.replace(".", "/")
        # Append metadata file extension
        metadata_file = f"{check_path_name}.metadata.json"
        # Load metadata
        check_metadata = load_check_metadata(metadata_file)
        bulk_check_metadata[check_metadata.CheckID] = check_metadata

    return bulk_check_metadata


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


# Exclude services to run
def exclude_services_to_run(
    checks_to_execute: set, excluded_services: list, provider: str
) -> set:
    # Recover checks from the input services
    for service in excluded_services:
        modules = recover_checks_from_provider(provider, service)
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


# Recover all checks from the selected provider and service
def recover_checks_from_provider(provider: str, service: str = None) -> list:
    checks = []
    modules = list_modules(provider, service)
    for module_name in modules:
        # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
        check_name = module_name.name
        if check_name.count(".") == 5:
            checks.append(check_name)
    return checks


# List all available modules in the selected provider and service
def list_modules(provider: str, service: str):
    module_path = f"providers.{provider}.services"
    if service:
        module_path += f".{service}"
    return walk_packages(
        importlib.import_module(module_path).__path__,
        importlib.import_module(module_path).__name__ + ".",
    )


# Import an input check using its path
def import_check(check_path: str) -> ModuleType:
    lib = importlib.import_module(f"{check_path}")
    return lib


def set_output_options(quiet):
    global output_options
    output_options = Output_From_Options(
        is_quiet=quiet
        # set input options here
    )
    return output_options


def run_check(check):
    print(
        f"\nCheck Name: {check.checkName} - {Fore.MAGENTA}{check.serviceName}{Fore.YELLOW} [{check.severity}]{Style.RESET_ALL}"
    )
    logger.debug(f"Executing check: {check.checkName}")
    findings = check.execute()
    report(findings, output_options)


def import_check(check_path: str) -> ModuleType:
    lib = importlib.import_module(f"{check_path}")
    return lib
