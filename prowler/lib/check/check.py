import functools
import importlib
import os
import sys
from pkgutil import walk_packages
from types import ModuleType

from alive_progress import alive_bar
from colorama import Fore, Style

from prowler.config.config import orange_color
from prowler.lib.check.compliance_models import load_compliance_framework
from prowler.lib.check.models import Check, load_check_metadata
from prowler.lib.logger import logger

try:
    lib = os.environ["PROWLER_REPORT_LIB_PATH"]
    outputs_module = importlib.import_module(lib)
    report = getattr(outputs_module, "report")
except KeyError:
    from prowler.lib.outputs.outputs import report
except Exception:
    sys.exit()

from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.outputs import Provider_Output_Options


# Load all checks metadata
def bulk_load_checks_metadata(provider: str) -> dict:
    bulk_check_metadata = {}
    checks = recover_checks_from_provider(provider)
    # Build list of check's metadata files
    for check_info in checks:
        # Build check path name
        check_name = check_info[0]
        check_path = check_info[1]
        # Append metadata file extension
        metadata_file = f"{check_path}/{check_name}.metadata.json"
        # Load metadata
        check_metadata = load_check_metadata(metadata_file)
        bulk_check_metadata[check_metadata.CheckID] = check_metadata

    return bulk_check_metadata


# Bulk load all compliance frameworks specification
def bulk_load_compliance_frameworks(provider: str) -> dict:
    """Bulk load all compliance frameworks specification into a dict"""
    try:
        bulk_compliance_frameworks = {}
        available_compliance_framework_modules = list_compliance_modules()
        for compliance_framework in available_compliance_framework_modules:
            if provider in compliance_framework.name:
                compliance_specification_dir_path = (
                    f"{compliance_framework.module_finder.path}/{provider}"
                )

                # for compliance_framework in available_compliance_framework_modules:
                for filename in os.listdir(compliance_specification_dir_path):
                    file_path = os.path.join(
                        compliance_specification_dir_path, filename
                    )
                    # Check if it is a file and ti size is greater than 0
                    if os.path.isfile(file_path) and os.stat(file_path).st_size > 0:
                        # Open Compliance file in JSON
                        # cis_v1.4_aws.json --> cis_v1.4_aws
                        compliance_framework_name = filename.split(".json")[0]
                        # Store the compliance info
                        bulk_compliance_frameworks[
                            compliance_framework_name
                        ] = load_compliance_framework(file_path)
    except Exception as e:
        logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")

    return bulk_compliance_frameworks


# Exclude checks to run
def exclude_checks_to_run(checks_to_execute: set, excluded_checks: list) -> set:
    for check in excluded_checks:
        checks_to_execute.discard(check)
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
                check_name = check_module[0].split(".")[-1]
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


def list_services(provider: str) -> set():
    available_services = set()
    checks_tuple = recover_checks_from_provider(provider)
    for _, check_path in checks_tuple:
        # Format: /absolute_path/prowler/providers/{provider}/services/{service_name}/{check_name}
        service_name = check_path.split("/")[-2]
        available_services.add(service_name)
    return sorted(available_services)


def list_categories(provider: str, bulk_checks_metadata: dict) -> set():
    available_categories = set()
    for check in bulk_checks_metadata.values():
        for cat in check.Categories:
            available_categories.add(cat)
    return available_categories


def print_categories(categories: set):
    print(
        f"There are {Fore.YELLOW}{len(categories)}{Style.RESET_ALL} available categories: \n"
    )
    for category in categories:
        print(f"- {category}")


def print_services(service_list: set):
    print(
        f"There are {Fore.YELLOW}{len(service_list)}{Style.RESET_ALL} available services: \n"
    )
    for service in service_list:
        print(f"- {service}")


def print_compliance_frameworks(
    bulk_compliance_frameworks: dict,
):
    print(
        f"There are {Fore.YELLOW}{len(bulk_compliance_frameworks.keys())}{Style.RESET_ALL} available Compliance Frameworks: \n"
    )
    for framework in bulk_compliance_frameworks.keys():
        print(f"\t- {Fore.YELLOW}{framework}{Style.RESET_ALL}")


def print_compliance_requirements(
    bulk_compliance_frameworks: dict, compliance_frameworks: list
):
    for compliance_framework in compliance_frameworks:
        for compliance in bulk_compliance_frameworks.values():
            # Workaround until we have more Compliance Frameworks
            split_compliance = compliance_framework.split("_")
            framework = split_compliance[0].upper()
            version = split_compliance[1].upper()
            provider = split_compliance[2].upper()
            if framework in compliance.Framework and compliance.Version == version:
                print(
                    f"Listing {framework} {version} {provider} Compliance Requirements:\n"
                )
                for requirement in compliance.Requirements:
                    checks = ""
                    for check in requirement.Checks:
                        checks += f" {Fore.YELLOW}\t\t{check}\n{Style.RESET_ALL}"
                    print(
                        f"Requirement Id: {Fore.MAGENTA}{requirement.Id}{Style.RESET_ALL}\n\t- Description: {requirement.Description}\n\t- Checks:\n{checks}"
                    )


def print_checks(
    provider: str,
    check_list: set,
    bulk_checks_metadata: dict,
):
    for check in check_list:
        try:
            print(
                f"[{bulk_checks_metadata[check].CheckID}] {bulk_checks_metadata[check].CheckTitle} - {Fore.MAGENTA}{bulk_checks_metadata[check].ServiceName} {Fore.YELLOW}[{bulk_checks_metadata[check].Severity}]{Style.RESET_ALL}"
            )
        except KeyError as error:
            logger.critical(
                f"Check {error} was not found for the {provider.upper()} provider"
            )
            sys.exit()

    print(
        f"\nThere are {Fore.YELLOW}{len(check_list)}{Style.RESET_ALL} available checks.\n"
    )


# Parse checks from compliance frameworks specification
def parse_checks_from_compliance_framework(
    compliance_frameworks: list, bulk_compliance_frameworks: dict
) -> list:
    """Parse checks from compliance frameworks specification"""
    checks_to_execute = set()
    try:
        for framework in compliance_frameworks:
            # compliance_framework_json["Requirements"][*]["Checks"]
            compliance_framework_checks_list = [
                requirement.Checks
                for requirement in bulk_compliance_frameworks[framework].Requirements
            ]
            # Reduce nested list into a list
            # Pythonic functional magic
            compliance_framework_checks = functools.reduce(
                lambda x, y: x + y, compliance_framework_checks_list
            )
            # Then union this list of checks with the initial one
            checks_to_execute = checks_to_execute.union(compliance_framework_checks)
    except Exception as e:
        logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")

    return checks_to_execute


def recover_checks_from_provider(provider: str, service: str = None) -> list[tuple]:
    """
    Recover all checks from the selected provider and service

    Returns a list of tuples with the following format (check_name, check_path)
    """
    try:
        checks = []
        modules = list_modules(provider, service)
        for module_name in modules:
            # Format: "prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"
            check_module_name = module_name.name
            # We need to exclude common shared libraries in services
            if check_module_name.count(".") == 6 and "lib" not in check_module_name:
                check_path = module_name.module_finder.path
                # Check name is the last part of the check_module_name
                check_name = check_module_name.split(".")[-1]
                check_info = (check_name, check_path)
                checks.append(check_info)
    except ModuleNotFoundError:
        logger.critical(f"Service {service} was not found for the {provider} provider.")
        sys.exit()
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
        sys.exit()
    else:
        return checks


def list_compliance_modules():
    """
    list_compliance_modules returns the available compliance frameworks and returns their path
    """
    # This module path requires the full path includig "prowler."
    module_path = "prowler.compliance"
    return walk_packages(
        importlib.import_module(module_path).__path__,
        importlib.import_module(module_path).__name__ + ".",
    )


# List all available modules in the selected provider and service
def list_modules(provider: str, service: str):
    # This module path requires the full path includig "prowler."
    module_path = f"prowler.providers.{provider}.services"
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


def run_check(check: Check, output_options: Provider_Output_Options) -> list:
    findings = []
    if output_options.verbose:
        print(
            f"\nCheck ID: {check.CheckID} - {Fore.MAGENTA}{check.ServiceName}{Fore.YELLOW} [{check.Severity}]{Style.RESET_ALL}"
        )
    logger.debug(f"Executing check: {check.CheckID}")
    try:
        findings = check.execute()
    except Exception as error:
        if not output_options.only_logs:
            print(
                f"Something went wrong in {check.CheckID}, please use --log-level ERROR"
            )
        logger.error(
            f"{check.CheckID} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    finally:
        return findings


def execute_checks(
    checks_to_execute: list,
    provider: str,
    audit_info: AWS_Audit_Info,
    audit_output_options: Provider_Output_Options,
) -> list:
    all_findings = []
    # Execution with the --only-logs flag
    if audit_output_options.only_logs:
        for check_name in checks_to_execute:
            # Recover service from check name
            service = check_name.split("_")[0]
            try:
                check_findings = execute(
                    service, check_name, provider, audit_output_options, audit_info
                )
                all_findings.extend(check_findings)

            # If check does not exists in the provider or is from another provider
            except ModuleNotFoundError:

                logger.critical(
                    f"Check '{check_name}' was not found for the {provider.upper()} provider"
                )
                sys.exit()
            except Exception as error:
                logger.error(
                    f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
    else:
        # Default execution
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
                bar.title = (
                    f"-> Scanning {orange_color}{service}{Style.RESET_ALL} service"
                )
                try:
                    check_findings = execute(
                        service, check_name, provider, audit_output_options, audit_info
                    )
                    all_findings.extend(check_findings)
                    bar()

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.critical(
                        f"Check '{check_name}' was not found for the {provider.upper()} provider"
                    )
                    bar.title = f"-> {Fore.RED}Scan was aborted!{Style.RESET_ALL}"
                    sys.exit()
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            bar.title = f"-> {Fore.GREEN}Scan completed!{Style.RESET_ALL}"
    return all_findings


def execute(
    service,
    check_name: str,
    provider: str,
    audit_output_options: Provider_Output_Options,
    audit_info: AWS_Audit_Info,
):
    # Import check module
    check_module_path = (
        f"prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"
    )
    lib = import_check(check_module_path)
    # Recover functions from check
    check_to_execute = getattr(lib, check_name)
    c = check_to_execute()
    # Run check
    check_findings = run_check(c, audit_output_options)
    report(check_findings, audit_output_options, audit_info)

    return check_findings
