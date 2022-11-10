import sys
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
        check_metadata = CheckMetadataModel.parse_file(metadata_file)
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


class CheckMetadataModel(BaseModel):
    """Check Metadata Model"""

    Provider: str
    CheckID: str
    CheckTitle: str
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
    # Compliance: List[Union[Compliance_Base_Model, dict]]


class Check(CheckMetadataModel):
    """Prowler Check"""

    def __init__(self, **data):
        """Check's init function. Calls the CheckMetadataModel init."""
        # Parse the Check's metadata file
        check_path_name = self.__class__.__module__.replace(".", "/")
        metadata_file = f"{check_path_name}.metadata.json"
        # Store it to validate them with Pydantic
        data = CheckMetadataModel.parse_file(metadata_file).dict()
        # data = load_check_metadata(metadata_file)
        # Calls parents init function
        super().__init__(**data)

    def metadata(self) -> dict:
        """Return the JSON representation of the check's metadata"""
        return self.json()

    # @abstractmethod
    # def execute(self):
    #     """Execute the check's logic"""


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
