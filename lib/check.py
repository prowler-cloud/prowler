import importlib
import json
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass

from lib.logger import logger
from lib.outputs import report


def load_checks_to_execute(check_list, provider):
    checks_to_execute = set()
    # LOADER
    # Handle if there are checks passed using -c/--checks
    if check_list:
        for check_name in check_list:
            checks_to_execute.add(check_name)

    # If there are no checks passed as argument
    else:
        # Get all check modules to run with the specific provider
        modules = recover_modules_from_provider(provider)
        for check_module in modules:
            # Recover check name from import path (last part)
            # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
            check_name = check_module.split(".")[-1]
            checks_to_execute.add(check_name)

    return checks_to_execute


def recover_modules_from_provider(provider):
    modules = []
    for module_name in pkgutil.walk_packages(
        importlib.import_module(f"providers.{provider}.services").__path__,
        importlib.import_module(f"providers.{provider}.services").__name__ + ".",
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


def import_check(check_path):
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
        f = open(metadata_file)
        check_metadata = json.load(f)
        return check_metadata

    # Validate metadata

    @abstractmethod
    def execute(self):
        pass
