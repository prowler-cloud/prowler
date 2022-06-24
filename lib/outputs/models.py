from dataclasses import dataclass

from config.config import timestamp
from lib.check.models import Check_Report, Organizations_Info


@dataclass
class Compliance_Framework:
    Framework: str
    Version: str
    Group: list
    Control: list


@dataclass
class Check_Output:
    STATUS: str
    REGION: str
    RESULT_EXTENDED: str
    PROFILE: str
    ACCOUNT_ID: int
    PROVIDER: str
    CHECKID: str
    CHECKNAME: str
    CHECKTITLE: str
    CHECKTYPE: str
    SERVICENAME: str
    SUBSERVICENAME: str
    RESOURCEIDTEMPLATE: str
    SEVERITY: str
    RESPOURCETYPE: str
    DESCRIPTION: str
    RISK: str
    RELATED_URL: str
    REMEDIATION_RECOMMENDATION_TEXT: str
    REMEDIATION_RECOMMENDATION_URL: str
    REMEDIATION_RECOMMENDATION_CODE_NATIVEIAC: str
    REMEDIATION_RECOMMENDATION_CODE_TERRAFORM: str
    REMEDIATION_RECOMMENDATION_CODE_CLI: str
    REMEDIATION_RECOMMENDATION_CODE_OTHER: str
    CATEGORIES: list
    TAGS: dict
    DEPENDS_ON: list
    RELATED_TO: list
    NOTES: str
    COMPLIANCE: list
    ASSESSMENT_TIME: str
    ACCOUNT_DETAILS_EMAIL: str
    ACCOUNT_DETAILS_NAME: str
    ACCOUNT_DETAILS_ARN: str
    ACCOUNT_DETAILS_ORG: str
    ACCOUNT_DETAILS_TAGS: str

    def __init__(
        self,
        account: str,
        profile: str,
        report: Check_Report,
        organizations: Organizations_Info,
    ):
        self.STATUS = report.status
        self.REGION = report.region
        self.RESULT_EXTENDED = report.result_extended
        self.ACCOUNT_ID = account
        self.PROFILE = profile
        self.PROVIDER = report.check_metadata.Provider
        self.CHECKID = report.check_metadata.CheckID
        self.CHECKNAME = report.check_metadata.CheckID
        self.CHECKTITLE = report.check_metadata.CheckTitle
        self.CHECKTYPE = report.check_metadata.CheckType
        self.SERVICENAME = report.check_metadata.ServiceName
        self.SUBSERVICENAME = report.check_metadata.SubServiceName
        self.RESOURCEIDTEMPLATE = report.check_metadata.ResourceIdTemplate
        self.SEVERITY = report.check_metadata.Severity
        self.RESPOURCETYPE = report.check_metadata.ResourceType
        self.DESCRIPTION = report.check_metadata.Description
        self.RISK = report.check_metadata.Risk
        self.RELATED_URL = report.check_metadata.RelatedUrl
        self.REMEDIATION_RECOMMENDATION_TEXT = report.check_metadata.Remediation[
            "Recommendation"
        ]["Text"]
        self.REMEDIATION_RECOMMENDATION_URL = report.check_metadata.Remediation[
            "Recommendation"
        ]["Url"]
        self.REMEDIATION_RECOMMENDATION_CODE_NATIVEIAC = (
            report.check_metadata.Remediation["Code"]["NativeIaC"]
        )
        self.REMEDIATION_RECOMMENDATION_CODE_TERRAFORM = (
            report.check_metadata.Remediation["Code"]["Terraform"]
        )
        self.REMEDIATION_RECOMMENDATION_CODE_CLI = report.check_metadata.Remediation[
            "Code"
        ]["cli"]
        self.REMEDIATION_RECOMMENDATION_CODE_OTHER = report.check_metadata.Remediation[
            "Code"
        ]["other"]
        self.CATEGORIES = self.__unroll_list__(
            report.check_metadata.Categories
        )  # report.check_metadata.Categories
        self.TAGS = self.__unroll_dict__(report.check_metadata.Tags)
        self.DEPENDS_ON = self.__unroll_list__(report.check_metadata.DependsOn)
        self.RELATED_TO = self.__unroll_list__(report.check_metadata.RelatedTo)
        self.NOTES = report.check_metadata.Notes
        self.COMPLIANCE = self.__unroll_compliance__(report.check_metadata.Compliance)
        self.ASSESSMENT_TIME = timestamp.isoformat()
        self.ACCOUNT_DETAILS_EMAIL = organizations.account_details_email
        self.ACCOUNT_DETAILS_NAME = organizations.account_details_name
        self.ACCOUNT_DETAILS_ARN = organizations.account_details_arn
        self.ACCOUNT_DETAILS_ORG = organizations.account_details_org
        self.ACCOUNT_DETAILS_TAGS = organizations.account_details_tags

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
                Framework=item["Framework"],
                Version=item["Version"],
                Group=item["Group"],
                Control=item["Control"],
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
