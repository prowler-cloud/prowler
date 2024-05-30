import importlib
import sys
from csv import DictWriter
from datetime import datetime
from typing import Any, List, Literal, Optional

from pydantic import BaseModel

from prowler.config.config import prowler_version, timestamp
from prowler.lib.check.models import Remediation
from prowler.lib.logger import logger
from prowler.lib.utils.utils import outputs_unix_timestamp
from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info


def get_check_compliance(finding, provider, output_options):
    try:
        check_compliance = {}
        # We have to retrieve all the check's compliance requirements
        if finding.check_metadata.CheckID in output_options.bulk_checks_metadata:
            for compliance in output_options.bulk_checks_metadata[
                finding.check_metadata.CheckID
            ].Compliance:
                compliance_fw = compliance.Framework
                if compliance.Version:
                    compliance_fw = f"{compliance_fw}-{compliance.Version}"
                # compliance.Provider == "Azure" or "GCP" or "AWS"
                if compliance.Provider.upper() == provider.upper():
                    if compliance_fw not in check_compliance:
                        check_compliance[compliance_fw] = []
                    for requirement in compliance.Requirements:
                        check_compliance[compliance_fw].append(requirement.Id)
        return check_compliance
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def generate_provider_output_csv(
    provider: str, finding, audit_info, mode: str, fd, output_options
):
    """
    set_provider_output_options configures automatically the outputs based on the selected provider and returns the Provider_Output_Options object.
    """
    try:
        # Dynamically load the Provider_Output_Options class
        finding_output_model = f"{provider.capitalize()}_Check_Output_{mode.upper()}"
        output_model = getattr(importlib.import_module(__name__), finding_output_model)
        # Fill common data among providers
        data = fill_common_data_csv(finding, output_options.unix_timestamp)

        if provider == "azure":
            data["resource_id"] = finding.resource_id
            data["resource_name"] = finding.resource_name
            data["subscription"] = finding.subscription
            data["tenant_domain"] = audit_info.identity.domain
            data["finding_unique_id"] = (
                f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.subscription}-{finding.resource_id}"
            )
            data["compliance"] = unroll_dict(
                get_check_compliance(finding, provider, output_options)
            )
            finding_output = output_model(**data)

        if provider == "gcp":
            data["resource_id"] = finding.resource_id
            data["resource_name"] = finding.resource_name
            data["project_id"] = finding.project_id
            data["location"] = finding.location.lower()
            data["finding_unique_id"] = (
                f"prowler-{provider}-{finding.check_metadata.CheckID}-{finding.project_id}-{finding.resource_id}"
            )
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
            data["finding_unique_id"] = (
                f"prowler-{provider}-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{finding.resource_id}"
            )
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


def fill_common_data_csv(finding: dict, unix_timestamp: bool) -> dict:
    data = {
        "assessment_start_time": outputs_unix_timestamp(unix_timestamp, timestamp),
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
    if tags and tags != [{}] and tags != [None]:
        for item in tags:
            # Check if there are tags in list
            if isinstance(item, dict):
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
        if isinstance(value, list):
            value = ", ".join(value)
        if not unrolled_items:
            unrolled_items = f"{key}: {value}"
        else:
            unrolled_items = f"{unrolled_items} {separator} {key}: {value}"

    return unrolled_items


def unroll_dict_to_list(dict: dict):
    dict_list = []
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
            dict_list.append(f"{key}: {value}")
        else:
            dict_list.append(f"{key}: {value}")

    return dict_list


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
    # __fields__ is always available in the Pydantic's BaseModel class
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
        finding_output.AssessmentStartTime = outputs_unix_timestamp(
            output_options.unix_timestamp, timestamp
        )
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
            finding_output.ProjectId = finding.project_id
            finding_output.Location = finding.location.lower()
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


class Check_Output_MITRE_ATTACK(BaseModel):
    """
    Check_Output_MITRE_ATTACK generates a finding's output in CSV MITRE ATTACK format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Tactics: str
    Requirements_SubTechniques: str
    Requirements_Platforms: str
    Requirements_TechniqueURL: str
    Requirements_Attributes_AWSServices: str
    Requirements_Attributes_Categories: str
    Requirements_Attributes_Values: str
    Requirements_Attributes_Comments: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


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
    Requirements_Attributes_ModoEjecucion: str
    Requirements_Attributes_Dependencias: Optional[str]
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


class Check_Output_CSV_AWS_CIS(BaseModel):
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


class Check_Output_CSV_GCP_CIS(BaseModel):
    """
    Check_Output_CSV_CIS generates a finding's output in CSV CIS format.
    """

    Provider: str
    Description: str
    ProjectId: str
    Location: str
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
    ResourceName: str
    CheckId: str


class Check_Output_CSV_AZURE_CIS(BaseModel):
    """
    Check_Output_CSV_CIS generates a finding's output in CSV CIS format.
    """

    Provider: str
    Description: str
    Subscription: str
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
    Requirements_Attributes_DefaultValue: str
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
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
    Requirements_Attributes_Service: Optional[str]
    Requirements_Attributes_Type: Optional[str]
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


class Check_Output_CSV_AWS_Well_Architected(BaseModel):
    """
    Check_Output_CSV_AWS_Well_Architected generates a finding's output in CSV AWS Well Architected Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Attributes_Name: str
    Requirements_Attributes_WellArchitectedQuestionId: str
    Requirements_Attributes_WellArchitectedPracticeId: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_LevelOfRisk: str
    Requirements_Attributes_AssessmentMethod: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_ImplementationGuidanceUrl: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str


class Check_Output_CSV_AWS_ISO27001_2013(BaseModel):
    """
    Check_Output_CSV_AWS_ISO27001_2013 generates a finding's output in CSV AWS ISO27001 Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Attributes_Category: str
    Requirements_Attributes_Objetive_ID: str
    Requirements_Attributes_Objetive_Name: str
    Requirements_Attributes_Check_Summary: str
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
    Tags: Optional[dict]


class Compliance(BaseModel):
    Status: str
    RelatedRequirements: List[str]
    AssociatedStandards: List[dict]


class Check_Output_JSON_ASFF(BaseModel):
    """
    Check_Output_JSON_ASFF generates a finding's output in JSON ASFF format: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
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


# JSON OCSF
class Remediation_OCSF(BaseModel):
    kb_articles: List[str]
    desc: str


class Finding(BaseModel):
    title: str
    desc: str
    supporting_data: dict
    remediation: Remediation_OCSF
    types: List[str]
    src_url: str
    uid: str
    related_events: List[str]


class Group(BaseModel):
    name: str


class Resources(BaseModel):
    group: Group
    region: str
    name: str
    uid: str
    labels: list
    type: str
    details: str


class Compliance_OCSF(BaseModel):
    status: str
    requirements: List[str]
    status_detail: str


class Account(BaseModel):
    name: str
    uid: str


class Organization(BaseModel):
    uid: str
    name: str


class Cloud(BaseModel):
    account: Optional[Account]
    region: str
    org: Optional[Organization]
    provider: str
    project_uid: str


class Feature(BaseModel):
    name: str
    uid: str
    version: str = prowler_version


class Product(BaseModel):
    language: str = "en"
    name: str = "Prowler"
    version: str = prowler_version
    vendor_name: str = "Prowler/ProwlerPro"
    feature: Feature


class Metadata(BaseModel):
    original_time: str
    profiles: List[str]
    product: Product
    version: str = "1.0.0-rc.3"


class Check_Output_JSON_OCSF(BaseModel):
    """
    Check_Output_JSON_OCSF generates a finding's output in JSON OCSF format.
    https://schema.ocsf.io/1.0.0-rc.3/classes/security_finding
    """

    finding: Finding
    resources: List[Resources]
    status_detail: str
    compliance: Compliance_OCSF
    message: str
    severity_id: Literal[0, 1, 2, 3, 4, 5, 6, 99]
    severity: Literal[
        "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other"
    ]
    cloud: Cloud
    time: datetime
    metadata: Metadata
    state_id: int = 0
    state: str = "New"
    status_id: Literal[0, 1, 2, 99]
    status: Literal["Unknown", "Success", "Failure", "Other"]
    type_uid: int = 200101
    type_name: str = "Security Finding: Create"
    impact_id: int = 0
    impact: str = "Unknown"
    confidence_id: int = 0
    confidence: str = "Unknown"
    activity_id: int = 1
    activity_name: str = "Create"
    category_uid: int = 2
    category_name: str = "Findings"
    class_uid: int = 2001
    class_name: str = "Security Finding"
