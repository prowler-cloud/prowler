from dataclasses import asdict, dataclass
from typing import List, Optional

from pydantic import BaseModel

from prowler.config.config import timestamp
from prowler.lib.check.models import Check_Report, Remediation
from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info


@dataclass
class Compliance_Framework:
    Framework: str
    Version: str
    Group: list
    Control: list


class Check_Output_JSON(BaseModel):
    AssessmentStartTime: str = ""
    FindingUniqueId: str = ""
    Provider: str
    Profile: str = ""
    AccountId: str = ""
    OrganizationsInfo: Optional[AWS_Organizations_Info]
    Region: str = ""
    CheckID: str
    CheckTitle: str
    CheckType: List[str]
    ServiceName: str
    SubServiceName: str
    Status: str = ""
    StatusExtended: str = ""
    Severity: str
    ResourceId: str = ""
    ResourceArn: str = ""
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
    # Compliance: List[ComplianceItem]


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


class Check_Output_CSV_ENS_RD2022(BaseModel):
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


@dataclass
class Check_Output_CSV:
    assessment_start_time: str
    finding_unique_id: str
    provider: str
    profile: str
    account_id: int
    account_name: str
    account_email: str
    account_arn: str
    account_org: str
    account_tags: str
    region: str
    check_id: str
    check_title: str
    check_type: str
    status: str
    status_extended: str
    service_name: str
    subservice_name: str
    severity: str
    resource_id: str
    resource_arn: str
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
    # compliance: str

    def get_csv_header(self):
        csv_header = []
        for key in asdict(self):
            csv_header = csv_header.append(key)
        return csv_header

    def __init__(
        self,
        account: str,
        profile: str,
        report: Check_Report,
        organizations: AWS_Organizations_Info,
    ):
        self.assessment_start_time = timestamp.isoformat()
        self.finding_unique_id = ""
        self.provider = report.check_metadata.Provider
        self.profile = profile
        self.account_id = account
        if organizations:
            self.account_name = organizations.account_details_name
            self.account_email = organizations.account_details_email
            self.account_arn = organizations.account_details_arn
            self.account_org = organizations.account_details_org
            self.account_tags = organizations.account_details_tags
        self.region = report.region
        self.check_id = report.check_metadata.CheckID
        self.check_title = report.check_metadata.CheckTitle
        self.check_type = report.check_metadata.CheckType
        self.status = report.status
        self.status_extended = report.status_extended
        self.service_name = report.check_metadata.ServiceName
        self.subservice_name = report.check_metadata.SubServiceName
        self.severity = report.check_metadata.Severity
        self.resource_id = report.resource_id
        self.resource_arn = report.resource_arn
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
        # self.compliance = self.__unroll_compliance__(report.check_metadata.Compliance)

    def __unroll_list__(self, listed_items: list):
        unrolled_items = ""
        separator = "|"
        for item in listed_items:
            if not unrolled_items:
                unrolled_items = f"{item}"
            else:
                unrolled_items = f"{unrolled_items}{separator}{item}"

        return unrolled_items

    def __unroll_dict__(self, dict_items: dict):
        unrolled_items = ""
        separator = "|"
        for key, value in dict_items.items():
            unrolled_item = f"{key}:{value}"
            if not unrolled_items:
                unrolled_items = f"{unrolled_item}"
            else:
                unrolled_items = f"{unrolled_items}{separator}{unrolled_item}"

        return unrolled_items

    def __unroll_compliance__(self, compliance: list):
        compliance_frameworks = []
        # fill list of dataclasses
        for item in compliance:
            compliance_framework = Compliance_Framework(
                Framework=item.Framework,
                Version=item.Version,
                Group=item.Group,
                Control=item.Control,
            )
            compliance_frameworks.append(compliance_framework)
        # iterate over list of dataclasses to output info
        unrolled_compliance = ""
        groups = ""
        controls = ""
        item_separator = ","
        framework_separator = "|"
        generic_separator = "/"
        for framework in compliance_frameworks:
            for group in framework.Group:
                if groups:
                    groups = f"{groups}{generic_separator}"
                groups = f"{groups}{group}"
            for control in framework.Control:
                if controls:
                    controls = f"{controls}{generic_separator}"
                controls = f"{controls}{control}"

            if unrolled_compliance:
                unrolled_compliance = f"{unrolled_compliance}{framework_separator}"
            unrolled_compliance = f"{unrolled_compliance}{framework.Framework}{item_separator}{framework.Version}{item_separator}{groups}{item_separator}{controls}"
            # unset groups and controls for next framework
            controls = ""
            groups = ""

        return unrolled_compliance
