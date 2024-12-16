import functools
import os
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Set

from pydantic import BaseModel, ValidationError, validator

from prowler.config.config import Provider
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.utils import recover_checks_from_provider
from prowler.lib.logger import logger


class Code(BaseModel):
    """
    Represents the remediation code using IaC like CloudFormation, Terraform or the native CLI.

    Attributes:
        NativeIaC (str): The NativeIaC code.
        Terraform (str): The Terraform code.
        CLI (str): The CLI code.
        Other (str): Other code.
    """

    NativeIaC: str
    Terraform: str
    CLI: str
    Other: str


class Recommendation(BaseModel):
    """
    Represents a recommendation.

    Attributes:
        Text (str): The text of the recommendation.
        Url (str): The URL associated with the recommendation.
    """

    Text: str
    Url: str


class Remediation(BaseModel):
    """
    Represents a remediation action for a specific .

    Attributes:
        Code (Code): The code associated with the remediation action.
        Recommendation (Recommendation): The recommendation for the remediation action.
    """

    Code: Code
    Recommendation: Recommendation


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class CheckMetadata(BaseModel):
    """
    Model representing the metadata of a check.

    Attributes:
        Provider (str): The provider of the check.
        CheckID (str): The ID of the check.
        CheckTitle (str): The title of the check.
        CheckType (list[str]): The type of the check.
        CheckAliases (list[str], optional): The aliases of the check. Defaults to an empty list.
        ServiceName (str): The name of the service.
        SubServiceName (str): The name of the sub-service.
        ResourceIdTemplate (str): The template for the resource ID.
        Severity (str): The severity of the check.
        ResourceType (str): The type of the resource.
        Description (str): The description of the check.
        Risk (str): The risk associated with the check.
        RelatedUrl (str): The URL related to the check.
        Remediation (Remediation): The remediation steps for the check.
        Categories (list[str]): The categories of the check.
        DependsOn (list[str]): The dependencies of the check.
        RelatedTo (list[str]): The related checks.
        Notes (str): Additional notes for the check.
        Compliance (list, optional): The compliance information for the check. Defaults to None.

    Validators:
        valid_category(value): Validator function to validate the categories of the check.
        severity_to_lower(severity): Validator function to convert the severity to lowercase.
        valid_severity(severity): Validator function to validate the severity of the check.
    """

    Provider: str
    CheckID: str
    CheckTitle: str
    CheckType: list[str]
    CheckAliases: list[str] = []
    ServiceName: str
    SubServiceName: str
    ResourceIdTemplate: str
    Severity: Severity
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

    @staticmethod
    def get_bulk(provider: str) -> dict[str, "CheckMetadata"]:
        """
        Load the metadata of all checks for a given provider reading the check's metadata files.
        Args:
            provider (str): The name of the provider.
        Returns:
            dict[str, CheckMetadata]: A dictionary containing the metadata of all checks, with the CheckID as the key.
        """

        bulk_check_metadata = {}
        checks = recover_checks_from_provider(provider)
        # Build list of check's metadata files
        for check_info in checks:
            # Build check path name
            check_name = check_info[0]
            check_path = check_info[1]
            # Ignore fixer files
            if check_name.endswith("_fixer"):
                continue
            # Append metadata file extension
            metadata_file = f"{check_path}/{check_name}.metadata.json"
            # Load metadata
            check_metadata = load_check_metadata(metadata_file)
            bulk_check_metadata[check_metadata.CheckID] = check_metadata

        return bulk_check_metadata

    @staticmethod
    def list(
        bulk_checks_metadata: dict = None,
        bulk_compliance_frameworks: dict = None,
        provider: str = None,
        severity: str = None,
        category: str = None,
        service: str = None,
        compliance_framework: str = None,
    ) -> Set["CheckMetadata"]:
        """
        Returns a set of checks from the bulk checks metadata.

        Args:
            provider (str): The provider of the checks.
            bulk_checks_metadata (dict): The bulk checks metadata.
            bulk_compliance_frameworks (dict): The bulk compliance frameworks.
            severity (str): The severity of the checks.
            category (str): The category of the checks.
            service (str): The service of the checks.
            compliance_framework (str): The compliance framework of the checks.

        Returns:
            set: A set of checks.
        """
        checks_from_provider = set()
        checks_from_severity = set()
        checks_from_category = set()
        checks_from_service = set()
        checks_from_compliance_framework = set()
        # If the bulk checks metadata is not provided, get it
        if not bulk_checks_metadata:
            bulk_checks_metadata = {}
            available_providers = [p.value for p in Provider]
            for provider_name in available_providers:
                bulk_checks_metadata.update(CheckMetadata.get_bulk(provider_name))
        if provider:
            checks_from_provider = {
                check_name
                for check_name, check_metadata in bulk_checks_metadata.items()
                if check_metadata.Provider == provider
            }
        if severity:
            checks_from_severity = CheckMetadata.list_by_severity(
                bulk_checks_metadata=bulk_checks_metadata, severity=severity
            )
        if category:
            checks_from_category = CheckMetadata.list_by_category(
                bulk_checks_metadata=bulk_checks_metadata, category=category
            )
        if service:
            checks_from_service = CheckMetadata.list_by_service(
                bulk_checks_metadata=bulk_checks_metadata, service=service
            )
        if compliance_framework:
            # Loaded here, as it is not always needed
            if not bulk_compliance_frameworks:
                bulk_compliance_frameworks = {}
                available_providers = [p.value for p in Provider]
                for provider in available_providers:
                    bulk_compliance_frameworks = Compliance.get_bulk(provider=provider)
            checks_from_compliance_framework = (
                CheckMetadata.list_by_compliance_framework(
                    bulk_compliance_frameworks=bulk_compliance_frameworks,
                    compliance_framework=compliance_framework,
                )
            )

        # Get all the checks:
        checks = set(bulk_checks_metadata.keys())
        # Get the intersection of the checks
        if len(checks_from_provider) > 0 or provider:
            checks = checks & checks_from_provider
        if len(checks_from_severity) > 0 or severity:
            checks = checks & checks_from_severity
        if len(checks_from_category) > 0 or category:
            checks = checks & checks_from_category
        if len(checks_from_service) > 0 or service:
            checks = checks & checks_from_service
        if len(checks_from_compliance_framework) > 0 or compliance_framework:
            checks = checks & checks_from_compliance_framework

        return checks

    @staticmethod
    def get(bulk_checks_metadata: dict, check_id: str) -> "CheckMetadata":
        """
        Returns the check metadata from the bulk checks metadata.

        Args:
            bulk_checks_metadata (dict): The bulk checks metadata.
            check_id (str): The check ID.

        Returns:
            CheckMetadata: The check metadata.
        """

        return bulk_checks_metadata.get(check_id, None)

    @staticmethod
    def list_by_severity(bulk_checks_metadata: dict, severity: str = None) -> set:
        """
        Returns a set of checks by severity from the bulk checks metadata.

        Args:
            bulk_checks_metadata (dict): The bulk checks metadata.
            severity (str): The severity.

        Returns:
            set: A set of checks by severity.
        """
        checks = set()

        if severity:
            checks = {
                check_name
                for check_name, check_metadata in bulk_checks_metadata.items()
                if check_metadata.Severity == severity
            }

        return checks

    @staticmethod
    def list_by_category(bulk_checks_metadata: dict, category: str = None) -> set:
        """
        Returns a set of checks by category from the bulk checks metadata.

        Args:
            bulk_checks_metadata (dict): The bulk checks metadata.
            category (str): The category.

        Returns:
            set: A set of checks by category.
        """
        checks = set()

        if category:
            checks = {
                check_name
                for check_name, check_metadata in bulk_checks_metadata.items()
                if category in check_metadata.Categories
            }

        return checks

    @staticmethod
    def list_by_service(bulk_checks_metadata: dict, service: str = None) -> set:
        """
        Returns a set of checks by service from the bulk checks metadata.

        Args:
            bulk_checks_metadata (dict): The bulk checks metadata.
            service (str): The service.

        Returns:
            set: A set of checks by service.
        """
        checks = set()

        if service:
            # This is a special case for the AWS provider since `lambda` is a reserved keyword in Python
            if service == "awslambda":
                service = "lambda"
            checks = {
                check_name
                for check_name, check_metadata in bulk_checks_metadata.items()
                if check_metadata.ServiceName == service
            }

        return checks

    @staticmethod
    def list_by_compliance_framework(
        bulk_compliance_frameworks: dict, compliance_framework: str = None
    ) -> set:
        """
        Returns a set of checks by compliance framework from the bulk compliance frameworks.

        Args:
            bulk_compliance_frameworks (dict): The bulk compliance frameworks.
            compliance_framework (str): The compliance framework.

        Returns:
            set: A set of checks by compliance framework.
        """
        checks = set()

        if compliance_framework:
            try:
                checks_from_framework_list = [
                    requirement.Checks
                    for requirement in bulk_compliance_frameworks[
                        compliance_framework
                    ].Requirements
                ]
                # Reduce nested list into a list
                # Pythonic functional magic
                checks_from_framework = functools.reduce(
                    lambda x, y: x + y, checks_from_framework_list
                )
                # Then union this list of checks with the initial one
                checks = checks.union(checks_from_framework)
            except Exception as e:
                logger.error(
                    f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}"
                )

        return checks


class Check(ABC, CheckMetadata):
    """Prowler Check"""

    def __init__(self, **data):
        """Check's init function. Calls the CheckMetadataModel init."""
        # Parse the Check's metadata file
        metadata_file = (
            os.path.abspath(sys.modules[self.__module__].__file__)[:-3]
            + ".metadata.json"
        )
        # Store it to validate them with Pydantic
        data = CheckMetadata.parse_file(metadata_file).dict()
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


@dataclass
class Check_Report:
    """Contains the Check's finding information."""

    status: str
    status_extended: str
    check_metadata: CheckMetadata
    resource_details: str
    resource_tags: list
    muted: bool

    def __init__(self, metadata):
        self.status = ""
        self.check_metadata = CheckMetadata.parse_raw(metadata)
        self.status_extended = ""
        self.resource_details = ""
        self.resource_tags = []
        self.muted = False


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
    location: str

    def __init__(self, metadata):
        super().__init__(metadata)
        self.resource_name = ""
        self.resource_id = ""
        self.subscription = ""
        self.location = "global"


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


@dataclass
class Check_Report_Kubernetes(Check_Report):
    # TODO change class name to CheckReportKubernetes
    """Contains the Kubernetes Check's finding information."""

    resource_name: str
    resource_id: str
    namespace: str

    def __init__(self, metadata):
        super().__init__(metadata)
        self.resource_name = ""
        self.resource_id = ""
        self.namespace = ""


# Testing Pending
def load_check_metadata(metadata_file: str) -> CheckMetadata:
    """
    Load check metadata from a file.
    Args:
        metadata_file (str): The path to the metadata file.
    Returns:
        CheckMetadata: The loaded check metadata.
    Raises:
        ValidationError: If the metadata file is not valid.
    """

    try:
        check_metadata = CheckMetadata.parse_file(metadata_file)
    except ValidationError as error:
        logger.critical(f"Metadata from {metadata_file} is not valid: {error}")
        # TODO: remove this exit and raise an exception
        sys.exit(1)
    else:
        return check_metadata
