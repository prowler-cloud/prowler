import sys
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel

from prowler.config.config import prowler_version
from prowler.lib.logger import logger


def get_check_compliance(finding, provider_type, output_options) -> dict:
    """get_check_compliance returns a map with the compliance framework as key and the requirements where the finding's check is present.

        Example:

    {
        "CIS-1.4": ["2.1.3"],
        "CIS-1.5": ["2.1.3"],
    }
    """
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
                if compliance.Provider == provider_type.upper():
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


def parse_json_tags(tags: list):
    dict_tags = {}
    if tags and tags != [{}] and tags != [None]:
        for tag in tags:
            if "Key" in tag and "Value" in tag:
                dict_tags[tag["Key"]] = tag["Value"]
            else:
                dict_tags.update(tag)

    return dict_tags


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
