import importlib
import sys
from csv import DictWriter
from typing import Any, List, Optional

from pydantic import BaseModel

from prowler.config.config import timestamp
from prowler.lib.check.models import Remediation
from prowler.lib.logger import logger
from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info


def get_check_compliance(finding, provider, output_options):
    check_compliance = {}
    # We have to retrieve all the check's compliance requirements
    for compliance in output_options.bulk_checks_metadata[
        finding.check_metadata.CheckID
    ].Compliance:
        compliance_fw = compliance.Framework
        if compliance.Version:
            compliance_fw = f"{compliance_fw}-{compliance.Version}"
        if compliance.Provider == provider.upper():
            if compliance_fw not in check_compliance:
                check_compliance[compliance_fw] = []
            for requirement in compliance.Requirements:
                check_compliance[compliance_fw].append(requirement.Id)
    return check_compliance


def generate_provider_output_csv(
    provider: str, finding, audit_info, mode: str, fd, output_options
):
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
            data["compliance"] = unroll_dict(
                get_check_compliance(finding, provider, output_options)
            )
            finding_output = output_model(**data)

        if provider == "gcp":
            data["resource_id"] = finding.resource_id
            data["resource_name"] = finding.resource_name
            data["project_id"] = finding.project_id
            data["location"] = finding.location
            data[
                "finding_unique_id"
            ] = f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.project_id}-{finding.resource_id}"
            data["compliance"] = unroll_dict(
                get_check_compliance(finding, provider, output_options)
            )
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
            data["compliance"] = unroll_dict(
                get_check_compliance(finding, provider, output_options)
            )
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
        "resource_tags": unroll_tags(finding.resource_tags),
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
        "categories": unroll_list(finding.check_metadata.Categories),
        "depends_on": unroll_list(finding.check_metadata.DependsOn),
        "related_to": unroll_list(finding.check_metadata.RelatedTo),
        "notes": finding.check_metadata.Notes,
    }
    return data


def unroll_list(listed_items: list):
    unrolled_items = ""
    separator = "|"
    if listed_items:
        for item in listed_items:
            if not unrolled_items:
                unrolled_items = f"{item}"
            else:
                unrolled_items = f"{unrolled_items} {separator} {item}"

    return unrolled_items


def unroll_tags(tags: list):
    unrolled_items = ""
    separator = "|"
    if tags:
        for item in tags:
            # Check if there are tags in list
            if type(item) == dict:
                for key, value in item.items():
                    if not unrolled_items:
                        # Check the pattern of tags (Key:Value or Key:key/Value:value)
                        if "Key" != key and "Value" != key:
                            unrolled_items = f"{key}={value}"
                        else:
                            if "Key" == key:
                                unrolled_items = f"{value}="
                            else:
                                unrolled_items = f"{value}"
                    else:
                        if "Key" != key and "Value" != key:
                            unrolled_items = (
                                f"{unrolled_items} {separator} {key}={value}"
                            )
                        else:
                            if "Key" == key:
                                unrolled_items = (
                                    f"{unrolled_items} {separator} {value}="
                                )
                            else:
                                unrolled_items = f"{unrolled_items}{value}"
            elif not unrolled_items:
                unrolled_items = f"{item}"
            else:
                unrolled_items = f"{unrolled_items} {separator} {item}"

    return unrolled_items


def unroll_dict(dict: dict):
    unrolled_items = ""
    separator = "|"
    for key, value in dict.items():
        if type(value) == list:
            value = ", ".join(value)
        if not unrolled_items:
            unrolled_items = f"{key}: {value}"
        else:
            unrolled_items = f"{unrolled_items} {separator} {key}: {value}"

    return unrolled_items


def parse_html_string(str: str):
    string = ""
    for elem in str.split(" | "):
        if elem:
            string += f"\n&#x2022;{elem}\n"

    return string


def parse_json_tags(tags: list):
    dict_tags = {}
    if tags and tags != [{}] and tags != [None]:
        for tag in tags:
            if "Key" in tag and "Value" in tag:
                dict_tags[tag["Key"]] = tag["Value"]
            else:
                dict_tags.update(tag)

    return dict_tags


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
    resource_tags: str
    description: str
    risk: str
    related_url: str
    remediation_recommendation_text: str
    remediation_recommendation_url: str
    remediation_recommendation_code_nativeiac: str
    remediation_recommendation_code_terraform: str
    remediation_recommendation_code_cli: str
    remediation_recommendation_code_other: str
    compliance: str
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


class Gcp_Check_Output_CSV(Check_Output_CSV):
    """
    Gcp_Check_Output_CSV generates a finding's output in CSV format for the GCP provider.
    """

    project_id: str = ""
    location: str = ""
    resource_id: str = ""
    resource_name: str = ""


def generate_provider_output_json(
    provider: str, finding, audit_info, mode: str, output_options
):
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
            finding_output.Compliance = get_check_compliance(
                finding, provider, output_options
            )

        if provider == "gcp":
            finding_output.ProjectId = audit_info.project_id
            finding_output.Location = finding.location
            finding_output.ResourceId = finding.resource_id
            finding_output.ResourceName = finding.resource_name
            finding_output.FindingUniqueId = f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.project_id}-{finding.resource_id}"
            finding_output.Compliance = get_check_compliance(
                finding, provider, output_options
            )

        if provider == "aws":
            finding_output.Profile = audit_info.profile
            finding_output.AccountId = audit_info.audited_account
            finding_output.Region = finding.region
            finding_output.ResourceId = finding.resource_id
            finding_output.ResourceArn = finding.resource_arn
            finding_output.ResourceTags = parse_json_tags(finding.resource_tags)
            finding_output.FindingUniqueId = f"prowler-{provider}-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{finding.resource_id}"
            finding_output.Compliance = get_check_compliance(
                finding, provider, output_options
            )

            if audit_info.organizations_metadata:
                finding_output.OrganizationsInfo = (
                    audit_info.organizations_metadata.__dict__
                )

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
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
    Description: str
    Risk: str
    RelatedUrl: str
    Remediation: Remediation
    Compliance: Optional[dict]
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
    ResourceTags: list = []

    def __init__(self, **metadata):
        super().__init__(**metadata)


class Azure_Check_Output_JSON(Check_Output_JSON):
    """
    Azure_Check_Output_JSON generates a finding's output in JSON format for the AWS provider.
    """

    Tenant_Domain: str = ""
    Subscription: str = ""
    ResourceId: str = ""
    ResourceName: str = ""

    def __init__(self, **metadata):
        super().__init__(**metadata)


class Gcp_Check_Output_JSON(Check_Output_JSON):
    """
    Gcp_Check_Output_JSON generates a finding's output in JSON format for the AWS provider.
    """

    ProjectId: str = ""
    ResourceId: str = ""
    ResourceName: str = ""
    Location: str = ""

    def __init__(self, **metadata):
        super().__init__(**metadata)


class Check_Output_CSV_ENS_RD2022(BaseModel):
    """
    Check_Output_CSV_ENS_RD2022 generates a finding's output in CSV ENS RD2022 format.
    """

    Provider: str
    Description: str
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
    Check_Output_CSV_CIS generates a finding's output in CSV CIS format.
    """

    Provider: str
    Description: str
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


class Check_Output_CSV_Generic_Compliance(BaseModel):
    """
    Check_Output_CSV_Generic_Compliance generates a finding's output in CSV Generic Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: Optional[str]
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_SubGroup: Optional[str]
    Requirements_Attributes_Service: str
    Requirements_Attributes_Soc_Type: Optional[str]
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
    AssociatedStandards: List[dict]


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
