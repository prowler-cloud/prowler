import functools
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from typing import Any, Dict, Optional, Set

from pydantic.v1 import BaseModel, Field, ValidationError, validator
from pydantic.v1.error_wrappers import ErrorWrapper

from prowler.config.config import EXTERNAL_TOOL_PROVIDERS, Provider
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.utils import recover_checks_from_provider
from prowler.lib.logger import logger

# Valid ResourceGroup values as defined in the RFC
VALID_RESOURCE_GROUPS = frozenset(
    {
        "compute",
        "container",
        "serverless",
        "database",
        "storage",
        "network",
        "IAM",
        "messaging",
        "security",
        "monitoring",
        "api_gateway",
        "ai_ml",
        "governance",
        "collaboration",
        "devops",
        "analytics",
    }
)

# Valid Categories as defined in the RFC
VALID_CATEGORIES = frozenset(
    {
        "encryption",
        "internet-exposed",
        "logging",
        "secrets",
        "resilience",
        "threat-detection",
        "trust-boundaries",
        "vulnerabilities",
        "cluster-security",
        "container-security",
        "node-security",
        "gen-ai",
        "ci-cd",
        "identity-access",
        "email-security",
        "forensics-ready",
        "software-supply-chain",
        "e3",
        "e5",
        "privilege-escalation",
        "ec2-imdsv1",
    }
)


@functools.lru_cache(maxsize=1)
def _load_aws_check_types_hierarchy() -> dict:
    """
    Load and cache the AWS CheckTypes hierarchy from the JSON config file.

    Returns:
        dict: The CheckTypes hierarchy, or empty dict if file not found.
    """
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        check_types_file = os.path.normpath(
            os.path.join(
                current_dir,
                "..",
                "..",
                "providers",
                "aws",
                "config",
                "check_types.json",
            )
        )

        if not os.path.exists(check_types_file):
            return {}

        with open(check_types_file, "r") as f:
            return json.load(f)

    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _validate_aws_check_type_in_config(check_type: str) -> bool:
    """
    Validate if a CheckType exists in the AWS config using direct lookups.
    Supports partial paths: namespace, namespace/category, namespace/category/classifier

    Args:
        check_type: The CheckType string to validate (e.g., "TTPs/Initial Access")

    Returns:
        bool: True if the CheckType path exists in the config hierarchy
    """
    if not check_type:
        return False

    hierarchy = _load_aws_check_types_hierarchy()
    if not hierarchy:
        return False

    path_parts = check_type.split("/")
    current_level = hierarchy
    for part in path_parts:
        if not isinstance(current_level, dict) or part not in current_level:
            return False
        current_level = current_level[part]

    return True


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
        AdditionalURLs (list[str]): Additional URLs related to the check. Defaults to an empty list.
        Categories (list[str]): The categories of the check.
        DependsOn (list[str]): The dependencies of the check.
        RelatedTo (list[str]): The related checks.
        Notes (str): Additional notes for the check.
        Compliance (list, optional): The compliance information for the check. Defaults to None.

    Validators:
        valid_category(value): Validator function to validate the categories of the check against predefined values.
        severity_to_lower(severity): Validator function to convert the severity to lowercase.
        valid_cli_command(remediation): Validator function to validate the CLI command is not an URL.
        valid_resource_type(resource_type): Validator function to validate the resource type is not empty.
        validate_service_name(service_name, values): Validator function to validate the service name matches CheckID.
        valid_check_id(check_id): Validator function to validate the CheckID format.
        validate_check_title(check_title): Validator function to validate CheckTitle max length (150 chars) and not starting with 'Ensure'.
        validate_related_url(related_url): Validator function to validate RelatedUrl is empty (deprecated field).
        validate_recommendation_url(remediation): Validator function to validate Recommendation URL points to Prowler Hub.
        validate_check_type(check_type, values): Validator function to validate CheckType - must be empty for non-AWS providers, no empty strings and predefined types validation for AWS.
        validate_description(description): Validator function to validate Description max length (400 chars).
        validate_risk(risk): Validator function to validate Risk max length (400 chars).
        validate_resource_group(resource_group): Validator function to validate ResourceGroup against predefined values.
        validate_additional_urls(additional_urls): Validator function to ensure AdditionalURLs contains no duplicates.
    """

    Provider: str
    CheckID: str
    CheckTitle: str
    CheckType: list[str]
    CheckAliases: list[str] = Field(default_factory=list)
    ServiceName: str
    SubServiceName: str
    ResourceIdTemplate: str
    Severity: Severity
    ResourceType: str
    ResourceGroup: str = Field(default="")
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    AdditionalURLs: list[str] = Field(default_factory=list)
    Categories: list[str]
    DependsOn: list[str]
    RelatedTo: list[str]
    Notes: str
    # We set the compliance to None to
    # store the compliance later if supplied
    Compliance: Optional[list[Any]] = Field(default_factory=list)

    @validator("Categories", each_item=True, pre=True, always=True)
    def valid_category(cls, value, values):
        if not isinstance(value, str):
            raise ValueError("Categories must be a list of strings")
        value_lower = value.lower()
        if not re.match("^[a-z0-9-]+$", value_lower):
            raise ValueError(
                f"Invalid category: {value}. Categories can only contain lowercase letters, numbers and hyphen '-'"
            )
        if (
            value_lower not in VALID_CATEGORIES
            and values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS
        ):
            raise ValueError(
                f"Invalid category: '{value_lower}'. Must be one of: {', '.join(sorted(VALID_CATEGORIES))}."
            )
        return value_lower

    @validator("Severity", pre=True, always=True)
    def severity_to_lower(severity):
        return severity.lower()

    @validator("Remediation")
    def valid_cli_command(remediation):
        if re.match(r"^https?://", remediation.Code.CLI):
            raise ValueError("CLI command cannot be an URL")
        return remediation

    @validator("ResourceType", pre=True, always=True)
    def valid_resource_type(resource_type):
        if not resource_type or not isinstance(resource_type, str):
            raise ValueError("ResourceType must be a non-empty string")
        return resource_type

    @validator("ServiceName", pre=True, always=True)
    def validate_service_name(cls, service_name, values):
        if not service_name:
            raise ValueError("ServiceName must be a non-empty string")

        check_id = values.get("CheckID")
        if check_id and values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            service_from_check_id = check_id.split("_")[0]
            if service_name != service_from_check_id:
                raise ValueError(
                    f"ServiceName {service_name} does not belong to CheckID {check_id}"
                )
            if not service_name.islower():
                raise ValueError(f"ServiceName {service_name} must be in lowercase")

        return service_name

    @validator("CheckID", pre=True, always=True)
    def valid_check_id(cls, check_id, values):
        if not check_id:
            raise ValueError("CheckID must be a non-empty string")

        if check_id and values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            if "-" in check_id:
                raise ValueError(
                    f"CheckID {check_id} contains a hyphen, which is not allowed"
                )

        return check_id

    @validator("CheckTitle", pre=True, always=True)
    def validate_check_title(cls, check_title, values):
        if values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            if len(check_title) > 150:
                raise ValueError(
                    f"CheckTitle must not exceed 150 characters, got {len(check_title)} characters"
                )
            if check_title.startswith("Ensure"):
                raise ValueError(
                    "CheckTitle must not start with 'Ensure'. Use a descriptive title that focuses on the security state."
                )
        return check_title

    @validator("RelatedUrl", pre=True, always=True)
    def validate_related_url(cls, related_url, values):
        if related_url and values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            raise ValueError("RelatedUrl must be empty. This field is deprecated.")
        return related_url

    @validator("Remediation")
    def validate_recommendation_url(cls, remediation, values):
        if values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            url = remediation.Recommendation.Url
            if url and not url.startswith("https://hub.prowler.com/"):
                raise ValueError(
                    f"Remediation Recommendation URL must point to Prowler Hub (https://hub.prowler.com/...), got '{url}'."
                )
        return remediation

    @validator("CheckType", pre=True, always=True)
    def validate_check_type(cls, check_type, values):
        provider = values.get("Provider", "").lower()

        # Non-AWS providers must have an empty CheckType list
        if provider != "aws" and provider not in EXTERNAL_TOOL_PROVIDERS:
            if check_type:
                raise ValueError(
                    f"CheckType must be empty for non-AWS providers. Got {check_type} for provider '{provider}'."
                )
            return check_type

        # Check for empty strings in the list - applies to AWS
        for i, check_type_item in enumerate(check_type):
            if not check_type_item or check_type_item.strip() == "":
                raise ValueError(
                    f"CheckType list cannot contain empty strings. Found empty string at index {i}."
                )

        # For AWS provider, validate against config hierarchy
        if provider == "aws":
            for check_type_item in check_type:
                if not _validate_aws_check_type_in_config(check_type_item):
                    raise ValueError(
                        f"Invalid CheckType: '{check_type_item}'. Must be a valid path in the AWS CheckType hierarchy. See prowler/providers/aws/config/check_types.json for valid values."
                    )

        return check_type

    @validator("Description", pre=True, always=True)
    def validate_description(cls, description, values):
        if values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            if len(description) > 400:
                raise ValueError(
                    f"Description must not exceed 400 characters, got {len(description)} characters"
                )
        return description

    @validator("Risk", pre=True, always=True)
    def validate_risk(cls, risk, values):
        if values.get("Provider") not in EXTERNAL_TOOL_PROVIDERS:
            if len(risk) > 400:
                raise ValueError(
                    f"Risk must not exceed 400 characters, got {len(risk)} characters"
                )
        return risk

    @validator("ResourceGroup", pre=True, always=True)
    def validate_resource_group(cls, resource_group):
        if resource_group and resource_group not in VALID_RESOURCE_GROUPS:
            raise ValueError(
                f"Invalid ResourceGroup: '{resource_group}'. Must be one of: {', '.join(sorted(VALID_RESOURCE_GROUPS))} or empty string."
            )
        return resource_group

    @validator("AdditionalURLs", pre=True, always=True)
    def validate_additional_urls(cls, additional_urls):
        if not isinstance(additional_urls, list):
            raise ValueError("AdditionalURLs must be a list")

        if any(not url or not url.strip() for url in additional_urls):
            raise ValueError("AdditionalURLs cannot contain empty items")

        if len(additional_urls) != len(set(additional_urls)):
            raise ValueError("AdditionalURLs cannot contain duplicate items")

        return additional_urls

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
            if service == "lambda":
                service = "awslambda"
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
        file_path = os.path.abspath(sys.modules[self.__module__].__file__)[:-3]

        # Parse the Check's metadata file
        metadata_file = file_path + ".metadata.json"
        # Store it to validate them with Pydantic
        data = CheckMetadata.parse_file(metadata_file).dict()
        # Calls parents init function
        super().__init__(**data)

        # Verify names consistency
        check_id = self.CheckID
        class_name = self.__class__.__name__
        # os.path.basename handles Windows and POSIX paths reliably
        file_name = os.path.basename(file_path)

        errors = []
        if check_id != class_name:
            errors.append(f"CheckID '{check_id}' != class name '{class_name}'")
        if check_id != file_name:
            errors.append(f"CheckID '{check_id}' != file name '{file_name}'")

        if errors:
            formatted_errors = [
                ErrorWrapper(ValueError(err), loc=("CheckID",)) for err in errors
            ]
            raise ValidationError(formatted_errors, model=CheckMetadata)

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
    resource: dict
    resource_details: str
    resource_tags: list
    muted: bool

    def __init__(self, metadata: Dict, resource: Any) -> None:
        """Initialize the Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
                      Only accepted dict, list, BaseModels (dict attribute), custom models (with to_dict attribute) and dataclasses.
        """
        self.status = ""
        self.check_metadata = CheckMetadata.parse_raw(metadata)
        if isinstance(resource, dict):
            self.resource = resource
        elif hasattr(resource, "dict"):
            self.resource = resource.dict()
        elif hasattr(resource, "to_dict"):
            self.resource = resource.to_dict()
        elif is_dataclass(resource):
            self.resource = asdict(resource)
        else:
            logger.error(
                f"Resource metadata {type(resource)} in {self.check_metadata.CheckID} could not be converted to dict"
            )
            self.resource = {}
        self.status_extended = ""
        self.resource_details = ""
        self.resource_tags = getattr(resource, "tags", []) if resource else []
        self.muted = False


@dataclass
class Check_Report_AWS(Check_Report):
    """Contains the AWS Check's finding information."""

    resource_id: str
    resource_arn: str
    region: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        super().__init__(metadata, resource)
        self.resource_id = (
            getattr(resource, "id", None) or getattr(resource, "name", None) or ""
        )
        self.resource_arn = getattr(resource, "arn", "")
        self.region = getattr(resource, "region", "")


@dataclass
class Check_Report_Azure(Check_Report):
    """Contains the Azure Check's finding information."""

    resource_name: str
    resource_id: str
    subscription: str
    location: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        """Initialize the Azure Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
        """
        super().__init__(metadata, resource)
        self.resource_name = getattr(
            resource, "name", getattr(resource, "resource_name", "")
        )
        self.resource_id = getattr(resource, "id", getattr(resource, "resource_id", ""))
        self.subscription = ""
        self.location = getattr(resource, "location", "global")


@dataclass
class Check_Report_GCP(Check_Report):
    """Contains the GCP Check's finding information."""

    resource_name: str
    resource_id: str
    project_id: str
    location: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        location=None,
        resource_name=None,
        resource_id=None,
        project_id=None,
    ) -> None:
        super().__init__(metadata, resource)
        self.resource_id = (
            resource_id
            or getattr(resource, "id", None)
            or getattr(resource, "name", None)
            or ""
        )

        # Prefer the explicit resource_name argument, otherwise look for a name attribute on the resource
        resource_name_candidate = resource_name or getattr(resource, "name", None)
        if not resource_name_candidate and isinstance(resource, dict):
            # Some callers pass a dict, so fall back to the dict entry if available
            resource_name_candidate = resource.get("name")
        if isinstance(resource_name_candidate, str):
            # Trim whitespace so empty strings collapse to the default
            resource_name_candidate = resource_name_candidate.strip()
        self.resource_name = (
            str(resource_name_candidate) if resource_name_candidate else "GCP Project"
        )
        self.project_id = project_id or getattr(resource, "project_id", "")
        self.location = (
            location
            or getattr(resource, "location", "")
            or getattr(resource, "region", "")
        )


@dataclass
class Check_Report_OCI(Check_Report):
    """Contains the OCI Check's finding information."""

    resource_name: str
    resource_id: str
    compartment_id: str
    region: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        region: str = None,
        resource_name: str = None,
        resource_id: str = None,
        compartment_id: str = None,
    ) -> None:
        """Initialize the OCI Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
            region: The region of the resource.
            resource_name: The name of the resource related with the finding.
            resource_id: The OCID of the resource related with the finding.
            compartment_id: The compartment OCID of the resource.
        """
        super().__init__(metadata, resource)
        self.resource_id = (
            resource_id
            or getattr(resource, "id", None)
            or getattr(resource, "name", None)
            or ""
        )
        self.resource_name = resource_name or getattr(resource, "name", "")
        self.compartment_id = compartment_id or getattr(resource, "compartment_id", "")
        self.region = region or getattr(resource, "region", "")


@dataclass
class CheckReportAlibabaCloud(Check_Report):
    """Contains the Alibaba Cloud Check's finding information."""

    resource_id: str
    resource_arn: str
    region: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        """Initialize the Alibaba Cloud Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource.
        """
        super().__init__(metadata, resource)
        self.resource_id = (
            getattr(resource, "id", None) or getattr(resource, "name", None) or ""
        )
        self.resource_arn = getattr(resource, "arn", "")
        self.region = getattr(resource, "region", "")


@dataclass
class Check_Report_Kubernetes(Check_Report):
    # TODO change class name to CheckReportKubernetes
    """Contains the Kubernetes Check's finding information."""

    resource_name: str
    resource_id: str
    namespace: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        super().__init__(metadata, resource)
        self.resource_id = (
            getattr(resource, "uid", None) or getattr(resource, "name", None) or ""
        )
        self.resource_name = getattr(resource, "name", "")
        self.namespace = getattr(resource, "namespace", "cluster-wide")
        if not self.namespace:
            self.namespace = "cluster-wide"


@dataclass
class CheckReportGithub(Check_Report):
    """Contains the GitHub Check's finding information."""

    resource_name: str
    resource_id: str
    owner: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        resource_name: str = None,
        resource_id: str = None,
        owner: str = None,
    ) -> None:
        """Initialize the GitHub Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
            resource_name: The name of the resource related with the finding.
            resource_id: The id of the resource related with the finding.
            owner: The owner of the resource related with the finding.
        """
        super().__init__(metadata, resource)
        self.resource_name = resource_name or getattr(resource, "name", "")
        self.resource_id = resource_id or getattr(resource, "id", "")
        self.owner = (
            owner
            or getattr(resource, "owner", "")  # For Repositories
            or getattr(resource, "name", "")  # For Organizations
        )


@dataclass
class CheckReportGoogleWorkspace(Check_Report):
    """Contains the Google Workspace Check's finding information."""

    resource_name: str
    resource_id: str
    customer_id: str
    location: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        resource_name: str = None,
        resource_id: str = None,
        customer_id: str = None,
        location: str = None,
    ) -> None:
        """Initialize the Google Workspace Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
            resource_name: The name of the resource related with the finding.
            resource_id: The id of the resource related with the finding.
            customer_id: The Google Workspace customer ID.
            location: The location of the resource (default: "global").
        """
        super().__init__(metadata, resource)
        self.resource_name = (
            resource_name
            or getattr(resource, "name", "")
            or getattr(resource, "email", "")
            or getattr(resource, "resource_name", "")
        )
        self.resource_id = (
            resource_id
            or getattr(resource, "id", "")
            or getattr(resource, "resource_id", "")
        )
        self.customer_id = customer_id or getattr(resource, "customer_id", "")
        self.location = location or getattr(resource, "location", "global")


@dataclass
class CheckReportCloudflare(Check_Report):
    """Contains the Cloudflare Check's finding information.

    Cloudflare is a global service - zones are resources, not regional contexts.
    All zone-related attributes are derived from the zone object passed as resource.
    """

    resource_name: str
    resource_id: str
    _zone: Any  # CloudflareZone object

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        resource_name: str = None,
        resource_id: str = None,
    ) -> None:
        """Initialize the Cloudflare Check's finding information.

        Args:
            metadata: Check metadata dictionary
            resource: The CloudflareZone resource being checked
            resource_name: Override for resource name
            resource_id: Override for resource ID
        """
        super().__init__(metadata, resource)

        # Zone is the resource being checked
        self._zone = resource

        self.resource_name = resource_name or getattr(
            resource, "name", getattr(resource, "resource_name", "")
        )
        self.resource_id = resource_id or getattr(
            resource, "id", getattr(resource, "resource_id", "")
        )

    @property
    def zone(self) -> Any:
        """The CloudflareZone object."""
        return self._zone

    @property
    def zone_id(self) -> str:
        """Zone ID."""
        return getattr(self._zone, "id", "")

    @property
    def zone_name(self) -> str:
        """Zone name - for DNS records use zone_name attribute, for zones use name."""
        zone_name = getattr(self._zone, "zone_name", None)
        if zone_name:
            return zone_name
        return getattr(self._zone, "name", "")

    @property
    def account_id(self) -> str:
        """Account ID derived from resource's account object or flat account_id."""
        zone_account = getattr(self._zone, "account", None)
        if zone_account:
            return getattr(zone_account, "id", "")
        return getattr(self._zone, "account_id", "")

    @property
    def region(self) -> str:
        """Return zone_name as region for zone-scoped resources, otherwise global."""
        zone_name = getattr(self._zone, "zone_name", None)
        if zone_name:
            return zone_name
        return "global"


@dataclass
class CheckReportM365(Check_Report):
    """Contains the M365 Check's finding information."""

    resource_name: str
    resource_id: str
    location: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        resource_name: str,
        resource_id: str,
        resource_location: str = "global",
    ) -> None:
        """Initialize the M365 Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
            resource_name: The name of the resource related with the finding.
            resource_id: The id of the resource related with the finding.
            resource_location: The location of the resource related with the finding.
        """
        super().__init__(metadata, resource)
        self.resource_name = resource_name
        self.resource_id = resource_id
        self.location = resource_location


@dataclass
class CheckReportIAC(Check_Report):
    """Contains the IAC Check's finding information using Trivy."""

    resource_name: str
    resource_line_range: str

    def __init__(
        self, metadata: dict = {}, finding: dict = {}, file_path: str = ""
    ) -> None:
        """
        Initialize the IAC Check's finding information from a Trivy misconfiguration dict.

        Args:
            metadata (Dict): Optional check metadata (can be None).
            finding (dict): A single misconfiguration result from Trivy's JSON output.
        """
        super().__init__(metadata, finding)

        self.resource = finding
        self.resource_name = file_path
        cause = finding.get("CauseMetadata", {})
        start = cause.get("StartLine") or finding.get("StartLine")
        end = cause.get("EndLine") or finding.get("EndLine")
        self.resource_line_range = f"{start}:{end}" if start else ""


@dataclass
class CheckReportImage(Check_Report):
    """Contains the Container Image Check's finding information using Trivy."""

    resource_name: str
    resource_id: str
    image_digest: str
    package_name: str
    installed_version: str
    fixed_version: str

    def __init__(
        self,
        metadata: Optional[dict] = None,
        finding: Optional[dict] = None,
        image_name: str = "",
    ) -> None:
        """
        Initialize the Container Image Check's finding information from a Trivy vulnerability/secret dict.

        Args:
            metadata (Dict): Check metadata.
            finding (dict): A single vulnerability/secret result from Trivy's JSON output.
            image_name (str): The container image name being scanned.
        """
        if metadata is None:
            metadata = {}
        if finding is None:
            finding = {}
        super().__init__(metadata, finding)

        self.resource_name = image_name
        self.resource_id = (
            finding.get("VulnerabilityID", "")
            or finding.get("RuleID", "")
            or finding.get("ID", "")
        )
        self.image_digest = finding.get("PkgID", "")
        self.package_name = finding.get("PkgName", "")
        self.installed_version = finding.get("InstalledVersion", "")
        self.fixed_version = finding.get("FixedVersion", "")


@dataclass
class CheckReportLLM(Check_Report):
    """Contains the LLM Check's finding information."""

    prompt: str
    response: str
    model: str

    def __init__(self, metadata: dict = {}, finding: dict = {}) -> None:
        """
        Initialize the LLM Check's finding information from a promptfoo finding dict.

        Args:
            metadata (Dict): Optional check metadata (can be None).
            finding (dict): A single finding result from promptfoo's JSON output.
        """
        super().__init__(metadata, finding)

        self.prompt = finding.get("prompt", {}).get("raw", "No prompt available.")
        self.response = finding.get("response", {}).get(
            "output", "No output available."
        )
        self.model = finding.get("provider", {}).get("id", "No model available.")


@dataclass
class CheckReportNHN(Check_Report):
    """Contains the NHN Check's finding information."""

    resource_name: str
    resource_id: str
    location: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        """Initialize the NHN Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
        """
        super().__init__(metadata, resource)
        self.resource_name = getattr(
            resource, "name", getattr(resource, "resource_name", "")
        )
        self.resource_id = getattr(resource, "id", getattr(resource, "resource_id", ""))
        self.location = getattr(resource, "location", "kr1")


@dataclass
class CheckReportOpenStack(Check_Report):
    """Contains the OpenStack Check's finding information."""

    resource_name: str
    resource_id: str
    project_id: str
    region: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        super().__init__(metadata, resource)
        self.resource_name = getattr(
            resource, "name", getattr(resource, "resource_name", "default")
        )
        self.resource_id = getattr(resource, "id", getattr(resource, "resource_id", ""))
        self.project_id = getattr(resource, "project_id", "")
        self.region = getattr(resource, "region", "global")


@dataclass
class CheckReportMongoDBAtlas(Check_Report):
    """Contains the MongoDB Atlas Check's finding information."""

    resource_name: str
    resource_id: str
    project_id: str
    location: str

    def __init__(self, metadata: Dict, resource: Any) -> None:
        """Initialize the MongoDB Atlas Check's finding information.

        Args:
            metadata: The metadata of the check.
            resource: Basic information about the resource. Defaults to None.
        """
        super().__init__(metadata, resource)
        self.resource_name = getattr(
            resource, "name", getattr(resource, "resource_name", "")
        )
        self.resource_id = getattr(resource, "id", getattr(resource, "resource_id", ""))
        self.project_id = getattr(resource, "project_id", "")
        self.location = getattr(resource, "location", self.project_id)


@dataclass
class CheckReportVercel(Check_Report):
    """Contains the Vercel Check's finding information.

    Vercel is a global platform - team_id is the scoping context.
    All resource-related attributes are derived from the resource object.
    """

    resource_name: str
    resource_id: str
    team_id: str

    def __init__(
        self,
        metadata: Dict,
        resource: Any,
        resource_name: str = None,
        resource_id: str = None,
        team_id: str = None,
    ) -> None:
        """Initialize the Vercel Check's finding information.

        Args:
            metadata: Check metadata dictionary
            resource: The Vercel resource being checked
            resource_name: Override for resource name
            resource_id: Override for resource ID
            team_id: Override for team ID
        """
        super().__init__(metadata, resource)
        self.resource_name = resource_name or getattr(
            resource, "name", getattr(resource, "resource_name", "")
        )
        self.resource_id = resource_id or getattr(
            resource, "id", getattr(resource, "resource_id", "")
        )
        self.team_id = team_id or getattr(resource, "team_id", "")

    @property
    def region(self) -> str:
        """Vercel is global - return 'global'."""
        return "global"


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
        raise error
    else:
        return check_metadata
