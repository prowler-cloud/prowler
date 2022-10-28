import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from pydantic import BaseModel, ValidationError

from lib.logger import logger


@dataclass
class Output_From_Options:
    is_quiet: bool
    output_modes: list
    output_directory: str
    security_hub_enabled: bool
    output_filename: str
    allowlist_file: str


# Testing Pending
def load_check_metadata(metadata_file: str) -> dict:
    try:
        check_metadata = Check_Metadata_Model.parse_file(metadata_file)
    except ValidationError as error:
        logger.critical(f"Metadata from {metadata_file} is not valid: {error}")
        sys.exit()
    else:
        return check_metadata


class ComplianceItem(BaseModel):
    Control: List[str]
    Framework: str
    Group: List[str]
    Version: str


class Code(BaseModel):
    NativeIaC: str
    Terraform: str
    CLI: str
    Other: str


class Recommendation(BaseModel):
    Text: str
    Url: str


class Remediation(BaseModel):
    Code: Code
    Recommendation: Recommendation


class Check_Metadata_Model(BaseModel):
    Provider: str
    CheckID: str
    # CheckName: str
    CheckTitle: str
    # CheckAlias: str
    CheckType: List[str]
    ServiceName: str
    SubServiceName: str
    ResourceIdTemplate: str
    Severity: str
    ResourceType: str
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    Categories: List[str]
    Tags: dict
    DependsOn: List[str]
    RelatedTo: List[str]
    Notes: str
    Compliance: List[ComplianceItem]


class Check(ABC):
    def __init__(self):
        # Load metadata from check
        check_path_name = self.__class__.__module__.replace(".", "/")
        metadata_file = f"{check_path_name}.metadata.json"
        self.__check_metadata__ = load_check_metadata(metadata_file)
        # Assign metadata values
        self.__Provider__ = self.__check_metadata__.Provider
        self.__CheckID__ = self.__check_metadata__.CheckID
        # self.__CheckName__ = self.__check_metadata__.CheckName
        self.__CheckTitle__ = self.__check_metadata__.CheckTitle
        # self.__CheckAlias__ = self.__check_metadata__.CheckAlias
        self.__CheckType__ = self.__check_metadata__.CheckType
        self.__ServiceName__ = self.__check_metadata__.ServiceName
        self.__SubServiceName__ = self.__check_metadata__.SubServiceName
        self.__ResourceIdTemplate__ = self.__check_metadata__.ResourceIdTemplate
        self.__Severity__ = self.__check_metadata__.Severity
        self.__ResourceType__ = self.__check_metadata__.ResourceType
        self.__Description__ = self.__check_metadata__.Description
        self.__Risk__ = self.__check_metadata__.Risk
        self.__RelatedUrl__ = self.__check_metadata__.RelatedUrl
        self.__Remediation__ = self.__check_metadata__.Remediation
        self.__Categories__ = self.__check_metadata__.Categories
        self.__Tags__ = self.__check_metadata__.Tags
        self.__DependsOn__ = self.__check_metadata__.DependsOn
        self.__RelatedTo__ = self.__check_metadata__.RelatedTo
        self.__Notes__ = self.__check_metadata__.Notes
        self.__Compliance__ = self.__check_metadata__.Compliance

    @property
    def provider(self):
        return self.__Provider__

    @property
    def checkID(self):
        return self.__CheckID__

    # @property
    # def checkName(self):
    #     return self.__CheckName__

    @property
    def checkTitle(self):
        return self.__CheckTitle__

    # @property
    # def checkAlias(self):
    #     return self.__CheckAlias__

    @property
    def checkType(self):
        return self.__CheckType__

    @property
    def serviceName(self):
        return self.__ServiceName__

    @property
    def subServiceName(self):
        return self.__SubServiceName__

    @property
    def resourceIdTemplate(self):
        return self.__ResourceIdTemplate__

    @property
    def severity(self):
        return self.__Severity__

    @property
    def resourceType(self):
        return self.__ResourceType__

    @property
    def description(self):
        return self.__Description__

    @property
    def relatedUrl(self):
        return self.__RelatedUrl__

    @property
    def risk(self):
        return self.__Risk__

    @property
    def remediation(self):
        return self.__Remediation__

    @property
    def categories(self):
        return self.__Categories__

    @property
    def tags(self):
        return self.__Tags__

    @property
    def dependsOn(self):
        return self.__DependsOn__

    @property
    def relatedTo(self):
        return self.__RelatedTo__

    @property
    def notes(self):
        return self.__Notes__

    @property
    def compliance(self):
        return self.__Compliance__

    @property
    def metadata(self):
        return self.__check_metadata__

    @abstractmethod
    def execute(self):
        pass


@dataclass
class Check_Report:
    status: str
    region: str
    status_extended: str
    check_metadata: dict
    resource_id: str
    resource_details: str
    resource_tags: list
    resource_arn: str

    def __init__(self, metadata):
        self.check_metadata = metadata
        self.status_extended = ""
        self.resource_details = ""
        self.resource_tags = []
        self.resource_id = ""
        self.resource_arn = ""
