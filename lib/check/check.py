import importlib
from pkgutil import walk_packages
from types import ModuleType
from typing import Any

from alive_progress import alive_bar
from colorama import Fore, Style

from config.config import groups_file
from lib.check.models import Check, Output_From_Options, load_check_metadata
from lib.logger import logger
from lib.outputs.outputs import report
from lib.utils.utils import open_file, parse_json_file
from providers.aws.lib.audit_info.models import AWS_Audit_Info


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


def list_services(provider: str) -> set:
    available_services = set()
    checks = recover_checks_from_provider(provider)
    for check_name in checks:
        # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
        service_name = check_name.split(".")[3]
        available_services.add(service_name)
    return sorted(available_services)


def print_services(service_list: set):
    print(
        f"There are {Fore.YELLOW}{len(service_list)}{Style.RESET_ALL} available services: \n"
    )
    for service in service_list:
        print(f"- {service}")


def print_checks(provider: str, check_list: set, bulk_checks_metadata: dict):
    for check in check_list:
        try:
            print(
                f"[{bulk_checks_metadata[check].CheckID}] {bulk_checks_metadata[check].CheckTitle} - {Fore.MAGENTA}{bulk_checks_metadata[check].ServiceName} {Fore.YELLOW}[{bulk_checks_metadata[check].Severity}]{Style.RESET_ALL}"
            )
        except KeyError as error:
            logger.error(
                f"Check {error} was not found for the {provider.upper()} provider"
            )
    print(
        f"\nThere are {Fore.YELLOW}{len(check_list)}{Style.RESET_ALL} available checks.\n"
    )


# List available groups
def list_groups(provider: str):
    groups = parse_groups_from_file(groups_file)
    print("Available Groups:")

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
        # We need to exclude common shared libraries in services
        if (
            check_name.count(".") == 5
            and "lib" not in check_name
            and "test" not in check_name
        ):
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


def set_output_options(
    quiet: bool,
    output_modes: list,
    input_output_directory: str,
    security_hub_enabled: bool,
    output_filename: str,
    allowlist_file: str,
    verbose: bool,
):
    global output_options
    output_options = Output_From_Options(
        is_quiet=quiet,
        output_modes=output_modes,
        output_directory=input_output_directory,
        security_hub_enabled=security_hub_enabled,
        output_filename=output_filename,
        allowlist_file=allowlist_file,
        verbose=verbose,
        # set input options here
    )
    return output_options


def run_check(check: Check, output_options: Output_From_Options) -> list:
    findings = []
    if output_options.verbose or output_options.is_quiet:
        print(
            f"\nCheck ID: {check.checkID} - {Fore.MAGENTA}{check.serviceName}{Fore.YELLOW} [{check.severity}]{Style.RESET_ALL}"
        )
    logger.debug(f"Executing check: {check.checkID}")
    try:
        findings = check.execute()
    except Exception as error:
        print(f"Something went wrong in {check.checkID}, please use --log-level ERROR")
        logger.error(
            f"{check.checkID} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    finally:
        return findings


def execute_checks(
    checks_to_execute: list,
    provider: str,
    audit_info: AWS_Audit_Info,
    audit_output_options: Output_From_Options,
) -> list:
    all_findings = []
    orange = "\033[38;5;208m"
    print(
        f"{Style.BRIGHT}Executing {len(checks_to_execute)} checks, please wait...{Style.RESET_ALL}\n"
    )
    with alive_bar(
        total=len(checks_to_execute),
        ctrl_c=False,
        bar="blocks",
        spinner="classic",
        stats=False,
        enrich_print=False,
    ) as bar:
        for check_name in checks_to_execute:
            # Recover service from check name
            service = check_name.split("_")[0]
            bar.title = f"-> Scanning {orange}{service}{Style.RESET_ALL} service"
            try:
                # Import check module
                check_module_path = (
                    f"providers.{provider}.services.{service}.{check_name}.{check_name}"
                )
                lib = import_check(check_module_path)
                # Recover functions from check
                check_to_execute = getattr(lib, check_name)
                c = check_to_execute()
                # Run check
                check_findings = run_check(c, audit_output_options)
                all_findings.extend(check_findings)
                report(check_findings, audit_output_options, audit_info)
                bar()

            # If check does not exists in the provider or is from another provider
            except ModuleNotFoundError:
                logger.error(
                    f"Check '{check_name}' was not found for the {provider.upper()} provider"
                )
    return all_findings
