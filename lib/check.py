import json
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Check_Report:
    status: str
    region: str
    result_extended: str


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
