import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from prowler.lib.logger import logger


class Code(BaseModel):
    """Check's remediation information using IaC like CloudFormation, Terraform or the native CLI"""

    NativeIaC: str
    Terraform: str
    CLI: str
    Other: str


class Recommendation(BaseModel):
    """Check's recommendation information"""

    Text: str
    Url: str


class Remediation(BaseModel):
    """Check's remediation: Code and Recommendation"""

    Code: Code
    Recommendation: Recommendation


class Check_Metadata_Model(BaseModel):
    """Check Metadata Model"""

    Provider: str
    CheckID: str
    CheckTitle: str
    CheckType: list[str]
    ServiceName: str
    SubServiceName: str
    ResourceIdTemplate: str
    Severity: str
    ResourceType: str
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    Categories: list[str]
    Tags: dict
    DependsOn: list[str]
    RelatedTo: list[str]
    Notes: str
    # We set the compliance to None to
    # store the compliance later if supplied
    Compliance: list = None


class Check(ABC, Check_Metadata_Model):
    """Prowler Check"""

    def __init__(self, **data):
        """Check's init function. Calls the CheckMetadataModel init."""
        # Parse the Check's metadata file
        metadata_file = os.path.abspath(sys.modules[self.__module__].__file__).replace(
            ".py", ".metadata.json"
        )
        # Store it to validate them with Pydantic
        data = Check_Metadata_Model.parse_file(metadata_file).dict()
        # Calls parents init function
        super().__init__(**data)

    def metadata(self) -> dict:
        """Return the JSON representation of the check's metadata"""
        return self.json()

    @abstractmethod
    def execute(self):
        """Execute the check's logic"""


@dataclass
class Check_Report:
    """Contains the Check's finding information."""

    status: str
    status_extended: str
    check_metadata: Check_Metadata_Model
    resource_details: str
    resource_tags: list

    def __init__(self, metadata):
        self.status = ""
        self.check_metadata = Check_Metadata_Model.parse_raw(metadata)
        self.status_extended = ""
        self.resource_details = ""
        self.resource_tags = []


@dataclass
class Check_Report_AWS(Check_Report):
    """Contains the AWS Check's finding information."""

    resource_id: str
    resource_arn: str
    region: str

    def __init__(self, metadata):
        super().__init__(metadata)
        self.resource_id = ""
        self.resource_arn = ""
        self.region = ""


@dataclass
class Check_Report_Azure(Check_Report):
    """Contains the Azure Check's finding information."""

    resource_name: str
    resource_id: str
    subscription: str

    def __init__(self, metadata):
        super().__init__(metadata)
        self.resource_name = ""
        self.resource_id = ""
        self.subscription = ""


# Testing Pending
def load_check_metadata(metadata_file: str) -> Check_Metadata_Model:
    """load_check_metadata loads and parse a Check's metadata file"""
    try:
        check_metadata = Check_Metadata_Model.parse_file(metadata_file)
    except ValidationError as error:
        logger.critical(f"Metadata from {metadata_file} is not valid: {error}")
        sys.exit()
    else:
        return check_metadata
