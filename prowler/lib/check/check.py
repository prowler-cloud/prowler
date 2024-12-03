import importlib
import json
import os
import re
import shutil
import sys
import traceback
from types import ModuleType
from typing import Any

from alive_progress import alive_bar
from colorama import Fore, Style

import prowler
from prowler.config.config import orange_color
from prowler.lib.check.custom_checks_metadata import update_check_metadata
from prowler.lib.check.models import Check
from prowler.lib.check.utils import recover_checks_from_provider
from prowler.lib.logger import logger
from prowler.lib.outputs.outputs import report
from prowler.lib.utils.utils import open_file, parse_json_file, print_boxes
from prowler.providers.common.models import Audit_Metadata


# Exclude checks to run
def exclude_checks_to_run(checks_to_execute: set, excluded_checks: list) -> set:
    for check in excluded_checks:
        checks_to_execute.discard(check)
    return checks_to_execute


# Exclude services to run
def exclude_services_to_run(
    checks_to_execute: set, excluded_services: list, provider: str
) -> set:
    excluded_services = [
        "awslambda" if service == "lambda" else service for service in excluded_services
    ]
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
    """parse_checks_from_file returns a set of checks read from the given file"""
    try:
        checks_to_execute = set()
        with open_file(input_file) as f:
            json_file = parse_json_file(f)

        for check_name in json_file[provider]:
            checks_to_execute.add(check_name)

        return checks_to_execute
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )


# Load checks from custom folder
def parse_checks_from_folder(provider, input_folder: str) -> set:
    # TODO: move the AWS-specific code into the provider
    try:
        custom_checks = set()
        # Check if input folder is a S3 URI
        if provider.type == "aws" and re.search(
            "^s3://([^/]+)/(.*?([^/]+))/$", input_folder
        ):
            bucket = input_folder.split("/")[2]
            key = ("/").join(input_folder.split("/")[3:])
            s3_resource = provider.session.current_session.resource("s3")
            bucket = s3_resource.Bucket(bucket)
            for obj in bucket.objects.filter(Prefix=key):
                if not os.path.exists(os.path.dirname(obj.key)):
                    os.makedirs(os.path.dirname(obj.key))
                if obj.key[-1] == "/":
                    continue
                bucket.download_file(obj.key, obj.key)
            input_folder = key
        # Import custom checks by moving the checks folders to the corresponding services
        with os.scandir(input_folder) as checks:
            for check in checks:
                if check.is_dir():
                    check_module = input_folder + "/" + check.name
                    # Copy checks to specific provider/service folder
                    check_service = check.name.split("_")[0]
                    prowler_dir = prowler.__path__
                    prowler_module = f"{prowler_dir[0]}/providers/{provider.type}/services/{check_service}/{check.name}"
                    if os.path.exists(prowler_module):
                        shutil.rmtree(prowler_module)
                    shutil.copytree(check_module, prowler_module)
                    custom_checks.add(check.name)
        return custom_checks
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


# Load checks from custom folder
def remove_custom_checks_module(input_folder: str, provider: str):
    # Check if input folder is a S3 URI
    s3_uri = False
    if provider == "aws" and re.search("^s3://([^/]+)/(.*?([^/]+))/$", input_folder):
        input_folder = ("/").join(input_folder.split("/")[3:])
        s3_uri = True

    with os.scandir(input_folder) as checks:
        for check in checks:
            if check.is_dir():
                # Remove imported checks
                check_service = check.name.split("_")[0]
                prowler_dir = prowler.__path__
                prowler_module = f"{prowler_dir[0]}/providers/{provider}/services/{check_service}/{check.name}"
                if os.path.exists(prowler_module):
                    shutil.rmtree(prowler_module)
                # test if the service only had the loaded custom checks to delete the folder
                prowler_service_module = prowler_module.rsplit("/", 1)[0]
                if not os.listdir(prowler_service_module):
                    shutil.rmtree(prowler_service_module)
                # If S3 URI, remove the downloaded folders
                if s3_uri and os.path.exists(input_folder):
                    shutil.rmtree(input_folder)


def list_services(provider: str) -> set:
    available_services = set()
    checks_tuple = recover_checks_from_provider(provider)
    for _, check_path in checks_tuple:
        # Format: /absolute_path/prowler/providers/{provider}/services/{service_name}/{check_name}
        if os.name == "nt":
            service_name = check_path.split("\\")[-2]
        else:
            service_name = check_path.split("/")[-2]
        available_services.add(service_name)
    return sorted(available_services)


def list_fixers(provider: str) -> set:
    available_fixers = set()
    checks = recover_checks_from_provider(provider, include_fixers=True)
    # Build list of check's metadata files
    for check_info in checks:
        # Build check path name
        check_name = check_info[0]
        # Ignore non fixer files
        if not check_name.endswith("_fixer"):
            continue
        # Remove _fixer suffix
        check_name = check_name.replace("_fixer", "")
        available_fixers.add(check_name)
    return sorted(available_fixers)


def list_categories(bulk_checks_metadata: dict) -> set:
    available_categories = set()
    for check in bulk_checks_metadata.values():
        for cat in check.Categories:
            if cat:
                available_categories.add(cat)
    return available_categories


def print_categories(categories: set):
    categories_num = len(categories)
    plural_string = f"\nThere are {Fore.YELLOW}{categories_num}{Style.RESET_ALL} available categories.\n"
    singular_string = f"\nThere is {Fore.YELLOW}{categories_num}{Style.RESET_ALL} available category.\n"

    message = plural_string if categories_num > 1 else singular_string
    for category in sorted(categories):
        print(f"- {category}")

    print(message)


def print_services(service_list: set):
    services_num = len(service_list)
    plural_string = f"\nThere are {Fore.YELLOW}{services_num}{Style.RESET_ALL} available services.\n"
    singular_string = (
        f"\nThere is {Fore.YELLOW}{services_num}{Style.RESET_ALL} available service.\n"
    )

    message = plural_string if services_num > 1 else singular_string

    for service in service_list:
        print(f"- {service}")

    print(message)


def print_fixers(fixers_list: set):
    fixers_num = len(fixers_list)
    plural_string = (
        f"\nThere are {Fore.YELLOW}{fixers_num}{Style.RESET_ALL} available fixers.\n"
    )
    singular_string = (
        f"\nThere is {Fore.YELLOW}{fixers_num}{Style.RESET_ALL} available fixer.\n"
    )

    message = plural_string if fixers_num > 1 else singular_string

    for service in fixers_list:
        print(f"- {service}")

    print(message)


def print_compliance_frameworks(
    bulk_compliance_frameworks: dict,
):
    frameworks_num = len(bulk_compliance_frameworks.keys())
    plural_string = f"\nThere are {Fore.YELLOW}{frameworks_num}{Style.RESET_ALL} available Compliance Frameworks.\n"
    singular_string = f"\nThere is {Fore.YELLOW}{frameworks_num}{Style.RESET_ALL} available Compliance Framework.\n"
    message = plural_string if frameworks_num > 1 else singular_string

    for framework in sorted(bulk_compliance_frameworks.keys()):
        print(f"- {framework}")

    print(message)


def print_compliance_requirements(
    bulk_compliance_frameworks: dict, compliance_frameworks: list
):
    for compliance_framework in compliance_frameworks:
        for key in bulk_compliance_frameworks.keys():
            framework = bulk_compliance_frameworks[key].Framework
            provider = bulk_compliance_frameworks[key].Provider
            version = bulk_compliance_frameworks[key].Version
            requirements = bulk_compliance_frameworks[key].Requirements
            # We can list the compliance requirements for a given framework using the
            # bulk_compliance_frameworks keys since they are the compliance specification file name
            if compliance_framework == key:
                print(
                    f"Listing {framework} {version} {provider} Compliance Requirements:\n"
                )
                for requirement in requirements:
                    checks = ""
                    for check in requirement.Checks:
                        checks += f" {Fore.YELLOW}\t\t{check}\n{Style.RESET_ALL}"
                    print(
                        f"Requirement Id: {Fore.MAGENTA}{requirement.Id}{Style.RESET_ALL}\n\t- Description: {requirement.Description}\n\t- Checks:\n{checks}"
                    )


def list_checks_json(provider: str, check_list: set):
    try:
        output = {provider: check_list}
        return json.dumps(output, indent=2, default=str)
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
        sys.exit(1)


def print_checks(
    provider: str,
    check_list: set,
    bulk_checks_metadata: dict,
):
    for check in check_list:
        try:
            print(
                f"[{bulk_checks_metadata[check].CheckID}] {bulk_checks_metadata[check].CheckTitle} - {Fore.MAGENTA}{bulk_checks_metadata[check].ServiceName} {Fore.YELLOW}[{bulk_checks_metadata[check].Severity.value}]{Style.RESET_ALL}"
            )
        except KeyError as error:
            logger.error(
                f"Check {error} was not found for the {provider.upper()} provider"
            )

    checks_num = len(check_list)
    plural_string = (
        f"\nThere are {Fore.YELLOW}{checks_num}{Style.RESET_ALL} available checks.\n"
    )
    singular_string = (
        f"\nThere is {Fore.YELLOW}{checks_num}{Style.RESET_ALL} available check.\n"
    )

    message = plural_string if checks_num > 1 else singular_string
    print(message)


# Import an input check using its path
def import_check(check_path: str) -> ModuleType:
    lib = importlib.import_module(f"{check_path}")
    return lib


def run_fixer(check_findings: list) -> int:
    """
    Run the fixer for the check if it exists and there are any FAIL findings
    Args:
        check_findings (list): list of findings
    Returns:
        int: number of fixed findings
    """
    try:
        # Map findings to each check
        findings_dict = {}
        fixed_findings = 0
        for finding in check_findings:
            if finding.check_metadata.CheckID not in findings_dict:
                findings_dict[finding.check_metadata.CheckID] = []
            findings_dict[finding.check_metadata.CheckID].append(finding)

        for check, findings in findings_dict.items():
            # Check if there are any FAIL findings for the check
            if any("FAIL" in finding.status for finding in findings):
                try:
                    check_module_path = f"prowler.providers.{findings[0].check_metadata.Provider}.services.{findings[0].check_metadata.ServiceName}.{check}.{check}_fixer"
                    lib = import_check(check_module_path)
                    fixer = getattr(lib, "fixer")
                except ModuleNotFoundError:
                    logger.error(f"Fixer method not implemented for check {check}")
                else:
                    print(
                        f"\nFixing fails for check {Fore.YELLOW}{check}{Style.RESET_ALL}..."
                    )
                    for finding in findings:
                        if finding.status == "FAIL":
                            # Check what type of fixer is:
                            # - If it is a fixer for a specific resource and region
                            # - If it is a fixer for a specific region
                            # - If it is a fixer for a specific resource
                            if (
                                "region" in fixer.__code__.co_varnames
                                and "resource_id" in fixer.__code__.co_varnames
                            ):
                                print(
                                    f"\t{orange_color}FIXING{Style.RESET_ALL} {finding.resource_id} in {finding.region}... "
                                )
                                if fixer(
                                    resource_id=finding.resource_id,
                                    region=finding.region,
                                ):
                                    fixed_findings += 1
                                    print(f"\t{Fore.GREEN}DONE{Style.RESET_ALL}")
                                else:
                                    print(f"\t{Fore.RED}ERROR{Style.RESET_ALL}")
                            elif "region" in fixer.__code__.co_varnames:
                                print(
                                    f"\t{orange_color}FIXING{Style.RESET_ALL} {finding.region}... "
                                )
                                if fixer(region=finding.region):
                                    fixed_findings += 1
                                    print(f"\t{Fore.GREEN}DONE{Style.RESET_ALL}")
                                else:
                                    print(f"\t{Fore.RED}ERROR{Style.RESET_ALL}")
                            else:
                                print(
                                    f"\t{orange_color}FIXING{Style.RESET_ALL} Resource {finding.resource_id}... "
                                )
                                if fixer(resource_id=finding.resource_id):
                                    fixed_findings += 1
                                    print(f"\t\t{Fore.GREEN}DONE{Style.RESET_ALL}")
                                else:
                                    print(f"\t\t{Fore.RED}ERROR{Style.RESET_ALL}")
        return fixed_findings
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def execute_checks(
    checks_to_execute: list,
    global_provider: Any,
    custom_checks_metadata: Any,
    config_file: str,
    output_options: Any,
) -> list:
    # List to store all the check's findings
    all_findings = []
    # Services and checks executed for the Audit Status
    services_executed = set()
    checks_executed = set()

    # Initialize the Audit Metadata
    # TODO: this should be done in the provider class
    global_provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=checks_to_execute,
        completed_checks=0,
        audit_progress=0,
    )

    # Refactor(CLI): This needs to be moved somewhere in the CLI
    if os.name != "nt":
        try:
            from resource import RLIMIT_NOFILE, getrlimit, setrlimit

            # Check ulimit for the maximum system open files
            soft, hard = getrlimit(RLIMIT_NOFILE)
            if soft < 4096:
                logger.info(
                    f"Your session file descriptors limit ({soft} open files) is below 4096. Updating file descriptors session limit to 4096 during execution only."
                )
                # Set the soft ulimit to 4096
                setrlimit(RLIMIT_NOFILE, (4096, hard))
        except Exception as error:
            logger.error("Unable to retrieve ulimit default settings")
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    # Set verbose flag
    verbose = False
    if hasattr(output_options, "verbose"):
        verbose = output_options.verbose
    elif hasattr(output_options, "fixer"):
        verbose = output_options.fixer

    # Execution with the --only-logs flag
    if output_options.only_logs:
        for check_name in checks_to_execute:
            # Recover service from check name
            service = check_name.split("_")[0]
            try:
                try:
                    # Import check module
                    check_module_path = f"prowler.providers.{global_provider.type}.services.{service}.{check_name}.{check_name}"
                    lib = import_check(check_module_path)
                    # Recover functions from check
                    check_to_execute = getattr(lib, check_name)
                    check = check_to_execute()
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                    )
                    continue
                if verbose:
                    print(
                        f"\nCheck ID: {check.CheckID} - {Fore.MAGENTA}{check.ServiceName}{Fore.YELLOW} [{check.Severity.value}]{Style.RESET_ALL}"
                    )
                check_findings = execute(
                    check,
                    global_provider,
                    custom_checks_metadata,
                    output_options,
                )
                report(check_findings, global_provider, output_options)
                all_findings.extend(check_findings)

                # Update Audit Status
                services_executed.add(service)
                checks_executed.add(check_name)
                global_provider.audit_metadata = update_audit_metadata(
                    global_provider.audit_metadata, services_executed, checks_executed
                )

            # If check does not exists in the provider or is from another provider
            except ModuleNotFoundError:
                logger.error(
                    f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                )
            except Exception as error:
                logger.error(
                    f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
    else:
        # Prepare your messages
        messages = [f"Config File: {Fore.YELLOW}{config_file}{Style.RESET_ALL}"]
        if global_provider.mutelist.mutelist_file_path:
            messages.append(
                f"Mutelist File: {Fore.YELLOW}{global_provider.mutelist.mutelist_file_path}{Style.RESET_ALL}"
            )
        if global_provider.type == "aws":
            messages.append(
                f"Scanning unused services and resources: {Fore.YELLOW}{global_provider.scan_unused_services}{Style.RESET_ALL}"
            )
        report_title = (
            f"{Style.BRIGHT}Using the following configuration:{Style.RESET_ALL}"
        )
        print_boxes(messages, report_title)
        # Default execution
        checks_num = len(checks_to_execute)
        plural_string = "checks"
        singular_string = "check"

        check_noun = plural_string if checks_num > 1 else singular_string
        print(
            f"{Style.BRIGHT}Executing {checks_num} {check_noun}, please wait...{Style.RESET_ALL}"
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
                    try:
                        # Import check module
                        check_module_path = f"prowler.providers.{global_provider.type}.services.{service}.{check_name}.{check_name}"
                        lib = import_check(check_module_path)
                        # Recover functions from check
                        check_to_execute = getattr(lib, check_name)
                        check = check_to_execute()
                    except ModuleNotFoundError:
                        logger.error(
                            f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                        )
                        continue
                    if verbose:
                        print(
                            f"\nCheck ID: {check.CheckID} - {Fore.MAGENTA}{check.ServiceName}{Fore.YELLOW} [{check.Severity.value}]{Style.RESET_ALL}"
                        )
                    check_findings = execute(
                        check,
                        global_provider,
                        custom_checks_metadata,
                        output_options,
                    )

                    report(check_findings, global_provider, output_options)

                    all_findings.extend(check_findings)
                    services_executed.add(service)
                    checks_executed.add(check_name)
                    global_provider.audit_metadata = update_audit_metadata(
                        global_provider.audit_metadata,
                        services_executed,
                        checks_executed,
                    )

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    # TODO: add more loggin here, we need the original exception -- traceback.print_last()
                    logger.error(
                        f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                    )
                except Exception as error:
                    # TODO: add more loggin here, we need the original exception -- traceback.print_last()
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                bar()
            bar.title = f"-> {Fore.GREEN}Scan completed!{Style.RESET_ALL}"

    return all_findings


def execute(
    check: Check,
    global_provider: Any,
    custom_checks_metadata: Any,
    output_options: Any = None,
):
    """
    Execute the check and report the findings

    Args:
        service (str): service name
        check_name (str): check name
        global_provider (Any): provider object
        custom_checks_metadata (Any): custom checks metadata
        output_options (Any): output options, depending on the provider

    Returns:
        list: list of findings
    """
    try:
        # Update check metadata to reflect that in the outputs
        if custom_checks_metadata and custom_checks_metadata["Checks"].get(
            check.CheckID
        ):
            check = update_check_metadata(
                check, custom_checks_metadata["Checks"][check.CheckID]
            )

        only_logs = False
        if hasattr(output_options, "only_logs"):
            only_logs = output_options.only_logs

        # Execute the check
        check_findings = []
        logger.debug(f"Executing check: {check.CheckID}")
        try:
            check_findings = check.execute()
        except Exception as error:
            if not only_logs:
                print(
                    f"Something went wrong in {check.CheckID}, please use --log-level ERROR"
                )
            logger.error(
                f"{check.CheckID} -- {error.__class__.__name__}[{traceback.extract_tb(error.__traceback__)[-1].lineno}]: {error}"
            )

        # Exclude findings per status
        if hasattr(output_options, "status") and output_options.status:
            check_findings = [
                finding
                for finding in check_findings
                if finding.status in output_options.status
            ]

        # Before returning the findings, we need to apply the mute list logic
        if hasattr(global_provider, "mutelist") and global_provider.mutelist.mutelist:
            is_finding_muted_args = {}
            if global_provider.type == "aws":
                is_finding_muted_args["aws_account_id"] = (
                    global_provider.identity.account
                )
            elif global_provider.type == "kubernetes":
                is_finding_muted_args["cluster"] = global_provider.identity.cluster

            for finding in check_findings:
                is_finding_muted_args["finding"] = finding
                finding.muted = global_provider.mutelist.is_finding_muted(
                    **is_finding_muted_args
                )

    except ModuleNotFoundError:
        logger.error(
            f"Check '{check.CheckID}' was not found for the {global_provider.type.upper()} provider"
        )
        check_findings = []
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return check_findings


def update_audit_metadata(
    audit_metadata: Audit_Metadata, services_executed: set, checks_executed: set
) -> Audit_Metadata:
    """update_audit_metadata returns the audit_metadata updated with the new status

    Updates the given audit_metadata using the length of the services_executed and checks_executed
    """
    try:
        audit_metadata.services_scanned = len(services_executed)
        audit_metadata.completed_checks = len(checks_executed)
        audit_metadata.audit_progress = (
            100 * len(checks_executed) / len(audit_metadata.expected_checks)
        )

        return audit_metadata

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
