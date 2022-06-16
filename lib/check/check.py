import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import ModuleType

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

    checks_from_groups = parse_groups_from_file(groups_file, excluded_groups, provider)
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


# Load checks from groups.json
def parse_groups_from_file(group_file: str, group_list: list, provider: str) -> set:
    checks_to_execute = set()
    f = open_file(group_file)
    available_groups = parse_json_file(f)

    for group in group_list:
        if group in available_groups[provider]:
            for check_name in available_groups[provider][group]:
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
            checks_to_execute = parse_groups_from_file(
                groups_file, group_list, provider
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


def run_check(check):
    print(f"\nCheck Name: {check.CheckName}")
    logger.debug(f"Executing check: {check.CheckName}")
    findings = check.execute()
    report(findings)


def import_check(check_path: str) -> ModuleType:
    lib = importlib.import_module(f"{check_path}")
    return lib


@dataclass
class Check_Report:
    status: str
    region: str
    result_extended: str

    def __init__(self):
        self.status = ""
        self.region = ""
        self.result_extended = ""


class Check(ABC):
    def __init__(self):
        try:
            self.metadata = self.__parse_metadata__(
                self.__class__.__module__.replace(".", "/") + ".metadata.json"
            )
            self.Provider = self.metadata["Provider"]
            self.CheckID = self.metadata["CheckID"]
            self.CheckName = self.metadata["CheckName"]
            self.CheckTitle = self.metadata["CheckTitle"]
            self.CheckAlias = self.metadata["CheckAlias"]
            self.CheckType = self.metadata["CheckType"]
            self.ServiceName = self.metadata["ServiceName"]
            self.SubServiceName = self.metadata["SubServiceName"]
            self.ResourceIdTemplate = self.metadata["ResourceIdTemplate"]
            self.Severity = self.metadata["Severity"]
            self.ResourceType = self.metadata["ResourceType"]
            self.Description = self.metadata["Description"]
            self.Risk = self.metadata["Risk"]
            self.RelatedUrl = self.metadata["RelatedUrl"]
            self.Remediation = self.metadata["Remediation"]
            self.Categories = self.metadata["Categories"]
            self.Tags = self.metadata["Tags"]
            self.DependsOn = self.metadata["DependsOn"]
            self.RelatedTo = self.metadata["RelatedTo"]
            self.Notes = self.metadata["Notes"]
            self.Compliance = self.metadata["Compliance"]
        except:
            print(f"Metadata check from file {self.__class__.__module__} not found")

    @property
    def provider(self):
        return self.Provider

    @property
    def checkID(self):
        return self.CheckID

    @property
    def checkName(self):
        return self.CheckName

    @property
    def checkTitle(self):
        return self.CheckTitle

    @property
    def checkAlias(self):
        return self.CheckAlias

    @property
    def checkType(self):
        return self.CheckType

    @property
    def serviceName(self):
        return self.ServiceName

    @property
    def subServiceName(self):
        return self.SubServiceName

    @property
    def resourceIdTemplate(self):
        return self.ResourceIdTemplate

    @property
    def resourceType(self):
        return self.ResourceType

    @property
    def description(self):
        return self.Description

    @property
    def relatedUrl(self):
        return self.RelatedUrl

    @property
    def remediation(self):
        return self.Remediation

    @property
    def categories(self):
        return self.Categories

    @property
    def tags(self):
        return self.Tags

    @property
    def relatedTo(self):
        return self.RelatedTo

    @property
    def notes(self):
        return self.Notes

    @property
    def compliance(self):
        return self.Compliance

    def __parse_metadata__(self, metadata_file):
        # Opening JSON file
        f = open_file(metadata_file)
        # Parse JSON
        check_metadata = parse_json_file(f)
        return check_metadata

    # Validate metadata

    @abstractmethod
    def execute(self):
        pass
