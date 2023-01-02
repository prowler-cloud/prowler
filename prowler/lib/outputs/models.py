import importlib
import sys
from csv import DictWriter
from typing import Any, List, Optional

from pydantic import BaseModel

from prowler.config.config import timestamp
from prowler.lib.check.models import Remediation
from prowler.lib.logger import logger
from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info


def generate_provider_output_csv(provider: str, finding, audit_info, mode: str, fd):
    """
    set_provider_output_options configures automatically the outputs based on the selected provider and returns the Provider_Output_Options object.
    """
    try:
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"
        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        # Dynamically load the Provider_Output_Options class
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"
        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        # Fill common data among providers
        data = fill_common_data_csv(finding)

        if provider == "azure":
            data["resource_id"] = finding.resource_id
            data["resource_name"] = finding.resource_name
            data["subscription"] = finding.subscription
            data["tenant_domain"] = audit_info.identity.domain
            data[
                "finding_unique_id"
            ] = f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.subscription}-{finding.resource_id}"
            finding_output = output_model(**data)

        if provider == "aws":
            data["profile"] = audit_info.profile
            data["account_id"] = audit_info.audited_account
            data["region"] = finding.region
            data["resource_id"] = finding.resource_id
            data["resource_arn"] = finding.resource_arn
            data[
                "finding_unique_id"
            ] = f"prowler-{provider}-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{finding.resource_id}"
            finding_output = output_model(**data)

            if audit_info.organizations_metadata:
                finding_output.account_name = (
                    audit_info.organizations_metadata.account_details_name
                )
                finding_output.account_email = (
                    audit_info.organizations_metadata.account_details_email
                )
                finding_output.account_arn = (
                    audit_info.organizations_metadata.account_details_arn
                )
                finding_output.account_org = (
                    audit_info.organizations_metadata.account_details_org
                )
                finding_output.account_tags = (
                    audit_info.organizations_metadata.account_details_tags
                )

        csv_writer = DictWriter(
            fd,
            fieldnames=generate_csv_fields(output_model),
            delimiter=";",
        )

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    else:
        return csv_writer, finding_output


def fill_common_data_csv(finding: dict) -> dict:
    data = {
        "assessment_start_time": timestamp.isoformat(),
        "finding_unique_id": "",
        "provider": finding.check_metadata.Provider,
        "check_id": finding.check_metadata.CheckID,
        "check_title": finding.check_metadata.CheckTitle,
        "check_type": ",".join(finding.check_metadata.CheckType),
        "status": finding.status,
        "status_extended": finding.status_extended,
        "service_name": finding.check_metadata.ServiceName,
        "subservice_name": finding.check_metadata.SubServiceName,
        "severity": finding.check_metadata.Severity,
        "resource_type": finding.check_metadata.ResourceType,
        "resource_details": finding.resource_details,
        "resource_tags": finding.resource_tags,
        "description": finding.check_metadata.Description,
        "risk": finding.check_metadata.Risk,
        "related_url": finding.check_metadata.RelatedUrl,
        "remediation_recommendation_text": (
            finding.check_metadata.Remediation.Recommendation.Text
        ),
        "remediation_recommendation_url": (
            finding.check_metadata.Remediation.Recommendation.Url
        ),
        "remediation_recommendation_code_nativeiac": (
            finding.check_metadata.Remediation.Code.NativeIaC
        ),
        "remediation_recommendation_code_terraform": (
            finding.check_metadata.Remediation.Code.Terraform
        ),
        "remediation_recommendation_code_cli": (
            finding.check_metadata.Remediation.Code.CLI
        ),
        "remediation_recommendation_code_other": (
            finding.check_metadata.Remediation.Code.Other
        ),
        "categories": __unroll_list__(finding.check_metadata.Categories),
        "depends_on": __unroll_list__(finding.check_metadata.DependsOn),
        "related_to": __unroll_list__(finding.check_metadata.RelatedTo),
        "notes": finding.check_metadata.Notes,
    }
    return data


def __unroll_list__(listed_items: list):
    unrolled_items = ""
    separator = "|"
    for item in listed_items:
        if not unrolled_items:
            unrolled_items = f"{item}"
        else:
            unrolled_items = f"{unrolled_items}{separator}{item}"

    return unrolled_items


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    # __fields__ is alwayis available in the Pydantic's BaseModel class
    for field in format.__dict__.get("__fields__").keys():
        csv_fields.append(field)
    return csv_fields


class Check_Output_CSV(BaseModel):
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
    description: str
    risk: str
    related_url: str
    remediation_recommendation_text: str
    remediation_recommendation_url: str
    remediation_recommendation_code_nativeiac: str
    remediation_recommendation_code_terraform: str
    remediation_recommendation_code_cli: str
    remediation_recommendation_code_other: str
    categories: str
    depends_on: str
    related_to: str
    notes: str


class Aws_Check_Output_CSV(Check_Output_CSV):
    """
    Aws_Check_Output_CSV generates a finding's output in CSV format for the AWS provider.
    """

    profile: Optional[str]
    account_id: int
    account_name: Optional[str]
    account_email: Optional[str]
    account_arn: Optional[str]
    account_org: Optional[str]
    account_tags: Optional[str]
    region: str
    resource_id: str
    resource_arn: str


class Azure_Check_Output_CSV(Check_Output_CSV):
    """
    Azure_Check_Output_CSV generates a finding's output in CSV format for the Azure provider.
    """

    tenant_domain: str = ""
    subscription: str = ""
    resource_id: str = ""
    resource_name: str = ""


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
            finding_output.FindingUniqueId = f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.subscription}-{finding.resource_id}"

        if provider == "aws":
            finding_output.Profile = audit_info.profile
            finding_output.AccountId = audit_info.audited_account
            finding_output.Region = finding.region
            finding_output.ResourceId = finding.resource_id
            finding_output.ResourceArn = finding.resource_arn
            finding_output.FindingUniqueId = f"prowler-{provider}-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{finding.resource_id}"

            if audit_info.organizations_metadata:
                finding_output.OrganizationsInfo = (
                    audit_info.organizations_metadata.__dict__
                )

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
