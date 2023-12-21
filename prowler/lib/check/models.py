import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import wraps

from pydantic import BaseModel, ValidationError
from pydantic.main import ModelMetaclass

from prowler.lib.logger import logger
from prowler.lib.ui.live_display import live_display


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


class CheckMeta(ModelMetaclass):
    """
    Dynamically decorates the execute function of all subclasses of the Check class

    By making CheckMeta inherit from ModelMetaclass, it ensures that all features provided by Pydantic's BaseModel (such as data validation, serialization, and so forth) are preserved. CheckMeta just adds additional behavior (decorator application) on top of the existing features.
    This also works because ModelMetaclass inherits from ABCMeta, as does the ABC class (its got to do with how metaclasses work when applying it to a class that inherits from other classes that have a metaclass).
    The primary role of CheckMeta is to automatically apply a decorator to the execute method of subclasses. This behavior does not conflict with the typical responsibilities of ModelMetaclass
    """

    def __new__(cls, name, bases, dct):
        if "execute" in dct and not getattr(
            dct["execute"], "__isabstractmethod__", False
        ):
            dct["execute"] = Check.update_title_with_findings_decorator(dct["execute"])
        return super(CheckMeta, cls).__new__(cls, name, bases, dct)


class Check(ABC, Check_Metadata_Model, metaclass=CheckMeta):
    """Prowler Check"""

    title_bar_task: int = None
    progress_task: int = None

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

        self.live_display_enabled = False
        service_section = live_display.get_service_section()
        if service_section:
            self.live_display_enabled = True

            self.title_bar_task = service_section.title_bar.add_task(
                f"{self.CheckTitle}...", start=False
            )

    def increment_task_progress(self):
        if self.live_display_enabled:
            current_section = live_display.get_service_section()
            current_section.task_progress.update(self.progress_task, advance=1)

    def start_task(self, message, count):
        if self.live_display_enabled:
            current_section = live_display.get_service_section()
            self.progress_task = current_section.task_progress.add_task(
                description=message, total=count, visible=True
            )

    def update_title_with_findings(self, findings):
        if self.live_display_enabled:
            current_section = live_display.get_service_section()
            # current_section.task_progress.remove_task(self.progress_task)
            total_failed = len(
                [report for report in findings if report.status == "FAIL"]
            )
            total_checked = len(findings)
            if total_failed == 0:
                message = f"{self.CheckTitle} [pass]All resources passed ({total_checked})[/pass]"
            else:
                message = f"{self.CheckTitle} [fail]{total_failed}/{total_checked} failed![/fail]"
            current_section.title_bar.update(
                task_id=self.title_bar_task, description=message
            )

    def metadata(self) -> dict:
        """Return the JSON representation of the check's metadata"""
        return self.json()

    @abstractmethod
    def execute(self):
        """Execute the check's logic"""

    @staticmethod
    def update_title_with_findings_decorator(func):
        """
        Decorator to update the title bar in the live_display with findings after executing a check.
        """

        @wraps(func)
        def wrapper(check_instance, *args, **kwargs):
            # Execute the original check's logic
            findings = func(check_instance, *args, **kwargs)

            # Update the title bar with the findings
            check_instance.update_title_with_findings(findings)

            return findings

        return wrapper


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
