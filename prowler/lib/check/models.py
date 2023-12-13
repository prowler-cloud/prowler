import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError
from rich.progress import Task

from prowler.lib.logger import logger
from prowler.lib.utils.ui import progress_manager


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


class Check(ABC, Check_Metadata_Model):
    """Prowler Check"""

    title_bar_task: Task = None
    progress_task: Task = None
    # title_bar: Any = None
    # task_progress: Any = None

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

        current_manager = progress_manager.get_current_manager()
        # Cant do this as it messes with self.metdata()
        # self.title_bar = current_manager.title_bar
        # self.task_progress = current_manager.task_progress

        self.title_bar_task = current_manager.title_bar.add_task(
            f"{self.CheckTitle}...", start=False
        )

    def increment_task_progress(self):
        current_manager = progress_manager.get_current_manager()
        current_manager.task_progress.update(self.progress_task, advance=1)

    def start_task(self, message, count):
        current_manager = progress_manager.get_current_manager()
        self.progress_task = current_manager.task_progress.add_task(
            task_id=self.progress_task, description=message, total=count, visible=True
        )

    def update_title_with_findings(self, findings):
        current_manager = progress_manager.get_current_manager()
        current_manager.task_progress.remove_task(self.progress_task)
        total_failed = len([report for report in findings if report.status == "FAIL"])
        total_checked = len(findings)
        if total_failed == 0:
            message = (
                f"{self.CheckTitle} [pass]All resources passed ({total_checked})[/pass]"
            )
        else:
            message = (
                f"{self.CheckTitle} [fail]{total_failed}/{total_checked} failed![/fail]"
            )
        current_manager.title_bar.update(
            task_id=self.title_bar_task, description=message
        )

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


@dataclass
class Check_Report_GCP(Check_Report):
    """Contains the GCP Check's finding information."""

    resource_name: str
    resource_id: str
    project_id: str
    location: str

    def __init__(self, metadata):
        super().__init__(metadata)
        self.resource_name = ""
        self.resource_id = ""
        self.project_id = ""
        self.location = ""


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
