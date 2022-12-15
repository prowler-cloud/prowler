from dataclasses import asdict, dataclass
from typing import List, Optional

from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.config.config import timestamp
from prowler.lib.check.models import Check_Report_AWS, Check_Report_Azure, Remediation
from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info
import importlib
import sys
from typing import Any
from csv import DictWriter


def generate_provider_output_csv(provider: str, finding, audit_info, mode: str, fd):
    """
    set_provider_output_options configures automatically the outputs based on the selected provider and returns the Provider_Output_Options object.
    """
    try:
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"
        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        # Dynamically load the Provider_Output_Options class
        # Aws_Check_Output_CSV
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"

        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        if provider == "azure":
            finding_output = output_model(audit_info, finding)
        if provider == "aws":
            finding_output = output_model(
                audit_info, finding, audit_info.organizations_metadata
            )
        csv_writer = DictWriter(
            fd,
            fieldnames=generate_csv_fields(output_model),
            delimiter=";",
        )

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit()
    else:
        return csv_writer, finding_output


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    for field in format.__dict__.get("__dataclass_fields__").keys():
        csv_fields.append(field)
    return csv_fields


@dataclass
class Check_Output_CSV:
    """
    Check_Output_CSV generates a finding's output in CSV format.

    This is the base CSV output model for every provider.
    """

    assessment_start_time: str
    finding_unique_id: str
    provider: str
    check_id: str
    check_title: str
    check_type: str
    status: str
    status_extended: str
    service_name: str
    subservice_name: str
    severity: str
    resource_type: str
    resource_details: str
    resource_tags: list
    description: dict
    risk: list
    related_url: list
    remediation_recommendation_text: str
    remediation_recommendation_url: list
    remediation_recommendation_code_nativeiac: str
    remediation_recommendation_code_terraform: str
    remediation_recommendation_code_cli: str
    remediation_recommendation_code_other: str
    categories: str
    depends_on: str
    related_to: str
    notes: str

    def get_csv_header(self):
        csv_header = []
        for key in asdict(self):
            csv_header = csv_header.append(key)
        return csv_header

    def __init__(
        self,
        report: Any,
    ):
        self.assessment_start_time = timestamp.isoformat()
        self.finding_unique_id = ""
        self.provider = report.check_metadata.Provider
        self.check_id = report.check_metadata.CheckID
        self.check_title = report.check_metadata.CheckTitle
        self.check_type = report.check_metadata.CheckType
        self.status = report.status
        self.status_extended = report.status_extended
        self.service_name = report.check_metadata.ServiceName
        self.subservice_name = report.check_metadata.SubServiceName
        self.severity = report.check_metadata.Severity
        self.resource_type = report.check_metadata.ResourceType
        self.resource_details = report.resource_details
        self.resource_tags = report.resource_tags
        self.description = report.check_metadata.Description
        self.risk = report.check_metadata.Risk
        self.related_url = report.check_metadata.RelatedUrl
        self.remediation_recommendation_text = (
            report.check_metadata.Remediation.Recommendation.Text
        )
        self.remediation_recommendation_url = (
            report.check_metadata.Remediation.Recommendation.Url
        )
        self.remediation_recommendation_code_nativeiac = (
            report.check_metadata.Remediation.Code.NativeIaC
        )
        self.remediation_recommendation_code_terraform = (
            report.check_metadata.Remediation.Code.Terraform
        )
        self.remediation_recommendation_code_cli = (
            report.check_metadata.Remediation.Code.CLI
        )
        self.remediation_recommendation_code_other = (
            report.check_metadata.Remediation.Code.Other
        )
        self.categories = self.__unroll_list__(report.check_metadata.Categories)
        self.depends_on = self.__unroll_list__(report.check_metadata.DependsOn)
        self.related_to = self.__unroll_list__(report.check_metadata.RelatedTo)
        self.notes = report.check_metadata.Notes

    def __unroll_list__(self, listed_items: list):
        unrolled_items = ""
        separator = "|"
        for item in listed_items:
            if not unrolled_items:
                unrolled_items = f"{item}"
            else:
                unrolled_items = f"{unrolled_items}{separator}{item}"

        return unrolled_items


@dataclass
class Aws_Check_Output_CSV(Check_Output_CSV):
    """
    Aws_Check_Output_CSV generates a finding's output in CSV format for the AWS provider.
    """

    profile: str
    account_id: int
    account_name: str
    account_email: str
    account_arn: str
    account_org: str
    account_tags: str
    region: str
    resource_id: str
    resource_arn: str

    def __init__(
        self,
        audit_info: Any,
        report: Check_Report_AWS,
        organizations: AWS_Organizations_Info,
    ):
        # Call to Check_Output_CSV to fill the finding information
        super().__init__(report)
        self.profile = audit_info.profile
        self.account_id = audit_info.audited_account
        if organizations:
            self.account_name = organizations.account_details_name
            self.account_email = organizations.account_details_email
            self.account_arn = organizations.account_details_arn
            self.account_org = organizations.account_details_org
            self.account_tags = organizations.account_details_tags
        self.region = report.region
        self.resource_id = report.resource_id
        self.resource_arn = report.resource_arn


@dataclass
class Azure_Check_Output_CSV(Check_Output_CSV):
    """
    Azure_Check_Output_CSV generates a finding's output in CSV format for the Azure provider.
    """

    tenant_domain: str = ""
    subscription: str = ""
    resource_id: str = ""
    resource_name: str = ""

    def __init__(
        self,
        audit_info,
        report: Check_Report_Azure,
    ):
        # Call to Check_Output_CSV to fill the finding information
        super().__init__(report)
        self.tenant_domain = audit_info.identity.domain
        self.subscription = report.subscription
        self.resource_id = report.resource_id
        self.resource_name = report.resource_name


def generate_provider_output_json(provider: str, finding, audit_info, mode: str, fd):
    """
    generate_provider_output_json configures automatically the outputs based on the selected provider and returns the Check_Output_JSON object.
    """
    try:
        # Dynamically load the Provider_Output_Options class for the JSON format
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"
        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        # Instantiate the class for the cloud provider
        finding_output = output_model(**finding.check_metadata.dict())
        # Fill common fields
        finding_output.AssessmentStartTime = timestamp.isoformat()
        finding_output.Status = finding.status
        finding_output.StatusExtended = finding.status_extended
        finding_output.ResourceDetails = finding.resource_details

        if provider == "azure":
            finding_output.Tenant_Domain = audit_info.identity.domain
            finding_output.Subscription = finding.subscription
            finding_output.ResourceId = finding.resource_id
            finding_output.ResourceName = finding.resource_name
        if provider == "aws":

            finding_output.Profile = audit_info.profile
            finding_output.AccountId = audit_info.audited_account
            if audit_info.organizations_metadata:
                finding_output.OrganizationsInfo = (
                    audit_info.organizations_metadata.__dict__
                )
            finding_output.Region = finding.region
            finding_output.ResourceId = finding.resource_id
            finding_output.ResourceArn = finding.resource_arn

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit()
    else:
        return finding_output


class Check_Output_JSON(BaseModel):
    """
    Check_Output_JSON generates a finding's output in JSON format.

    This is the base JSON output model for every provider.
    """

    AssessmentStartTime: str = ""
    FindingUniqueId: str = ""
    Provider: str
    CheckID: str
    CheckTitle: str
    CheckType: List[str]
    ServiceName: str
    SubServiceName: str
    Status: str = ""
    StatusExtended: str = ""
    Severity: str
    ResourceType: str
    ResourceDetails: str = ""
    Tags: dict
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    Categories: List[str]
    DependsOn: List[str]
    RelatedTo: List[str]
    Notes: str


class Aws_Check_Output_JSON(Check_Output_JSON):
    """
    Aws_Check_Output_JSON generates a finding's output in JSON format for the AWS provider.
    """

    Profile: str = ""
    AccountId: str = ""
    OrganizationsInfo: Optional[AWS_Organizations_Info]
    Region: str = ""
    ResourceId: str = ""
    ResourceArn: str = ""

    def __init__(self, **metadata):
        super().__init__(**metadata)


class Azure_Check_Output_JSON(Check_Output_JSON):
    """
    Aws_Check_Output_JSON generates a finding's output in JSON format for the AWS provider.
    """

    Tenant_Domain: str = ""
    Subscription: str = ""
    ResourceId: str = ""
    ResourceName: str = ""

    def __init__(self, **metadata):
        super().__init__(**metadata)


######################################################
######################################################
######################################################
######################################################
######################################################
######################################################
######################################################
######################################################
######################################################
class Check_Output_CSV_ENS_RD2022(BaseModel):
    """
    Check_Output_CSV_ENS_RD2022 generates a finding's output in CSV ENS RD2022 format.
    """

    Provider: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_IdGrupoControl: str
    Requirements_Attributes_Marco: str
    Requirements_Attributes_Categoria: str
    Requirements_Attributes_DescripcionControl: str
    Requirements_Attributes_Nivel: str
    Requirements_Attributes_Tipo: str
    Requirements_Attributes_Dimensiones: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


class Check_Output_CSV_CIS(BaseModel):
    """
    Check_Output_CSV_ENS_RD2022 generates a finding's output in CSV CIS format.
    """

    Provider: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_Profile: str
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


# JSON ASFF Output
class ProductFields(BaseModel):
    ProviderName: str = "Prowler"
    ProviderVersion: str
    ProwlerResourceName: str


class Severity(BaseModel):
    Label: str


class Resource(BaseModel):
    Type: str
    Id: str
    Partition: str
    Region: str


class Compliance(BaseModel):
    Status: str
    RelatedRequirements: List[str]


class Check_Output_JSON_ASFF(BaseModel):
    """
    Check_Output_JSON_ASFF generates a finding's output in JSON ASFF format.
    """

    SchemaVersion: str = "2018-10-08"
    Id: str = ""
    ProductArn: str = ""
    RecordState: str = "ACTIVE"
    ProductFields: ProductFields = None
    GeneratorId: str = ""
    AwsAccountId: str = ""
    Types: List[str] = None
    FirstObservedAt: str = ""
    UpdatedAt: str = ""
    CreatedAt: str = ""
    Severity: Severity = None
    Title: str = ""
    Description: str = ""
    Resources: List[Resource] = None
    Compliance: Compliance = None
    Remediation: dict = None
