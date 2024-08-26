import os
import re
import sys
from abc import ABC, abstractmethod

from pydantic import BaseModel, ValidationError, validator

from prowler.config.config import valid_severities
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
    CheckAliases: list[str] = []
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
    DependsOn: list[str]
    RelatedTo: list[str]
    Notes: str
    # We set the compliance to None to
    # store the compliance later if supplied
    Compliance: list = None

    @validator("Categories", each_item=True, pre=True, always=True)
    def valid_category(value):
        if not isinstance(value, str):
            raise ValueError("Categories must be a list of strings")
        value_lower = value.lower()
        if not re.match("^[a-z-]+$", value_lower):
            raise ValueError(
                f"Invalid category: {value}. Categories can only contain lowercase letters and hyphen '-'"
            )
        return value_lower

    @validator("Severity", pre=True, always=True)
    def severity_to_lower(severity):
        return severity.lower()

    @validator("Severity")
    def valid_severity(severity):
        if severity not in valid_severities:
            raise ValueError(
                f"Invalid severity: {severity}. Severity must be one of {', '.join(valid_severities)}"
            )
        return severity


class Check(ABC, Check_Metadata_Model):
    """Prowler Check"""

    def __init__(self, **data):
        """Check's init function. Calls the CheckMetadataModel init."""
        # Parse the Check's metadata file
        metadata_file = (
            os.path.abspath(sys.modules[self.__module__].__file__)[:-3]
            + ".metadata.json"
        )
        # Store it to validate them with Pydantic
        data = Check_Metadata_Model.parse_file(metadata_file).dict()
        # Calls parents init function
        super().__init__(**data)
        # TODO: verify that the CheckID is the same as the filename and classname
        # to mimic the test done at test_<provider>_checks_metadata_is_valid

    def metadata(self) -> dict:
        """Return the JSON representation of the check's metadata"""
        return self.json()

    @abstractmethod
    def execute(self) -> list:
        """Execute the check's logic"""


# Testing Pending
def load_check_metadata(metadata_file: str) -> Check_Metadata_Model:
    """load_check_metadata loads and parse a Check's metadata file"""
    try:
        check_metadata = Check_Metadata_Model.parse_file(metadata_file)
    except ValidationError as error:
        logger.critical(f"Metadata from {metadata_file} is not valid: {error}")
        sys.exit(1)
    else:
        return check_metadata
