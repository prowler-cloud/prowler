from csv import DictWriter
from typing import List

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.outputs.utils import unroll_dict, unroll_list


class CSV(Output):
    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into the CSV format.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        try:
            for finding in findings:
                finding_dict = {}
                finding_dict["AUTH_METHOD"] = finding.auth_method
                finding_dict["TIMESTAMP"] = finding.timestamp
                finding_dict["ACCOUNT_UID"] = finding.account_uid
                finding_dict["ACCOUNT_NAME"] = finding.account_name
                finding_dict["ACCOUNT_EMAIL"] = finding.account_email
                finding_dict["ACCOUNT_ORGANIZATION_UID"] = (
                    finding.account_organization_uid
                )
                finding_dict["ACCOUNT_ORGANIZATION_NAME"] = (
                    finding.account_organization_name
                )
                finding_dict["ACCOUNT_TAGS"] = unroll_dict(
                    finding.account_tags, separator=":"
                )
                finding_dict["FINDING_UID"] = finding.uid
                finding_dict["PROVIDER"] = finding.metadata.Provider
                finding_dict["CHECK_ID"] = finding.metadata.CheckID
                finding_dict["CHECK_TITLE"] = finding.metadata.CheckTitle
                finding_dict["CHECK_TYPE"] = unroll_list(finding.metadata.CheckType)
                finding_dict["STATUS"] = finding.status.value
                finding_dict["STATUS_EXTENDED"] = finding.status_extended
                finding_dict["MUTED"] = finding.muted
                finding_dict["SERVICE_NAME"] = finding.metadata.ServiceName
                finding_dict["SUBSERVICE_NAME"] = finding.metadata.SubServiceName
                finding_dict["SEVERITY"] = finding.metadata.Severity.value
                finding_dict["RESOURCE_TYPE"] = finding.metadata.ResourceType
                finding_dict["RESOURCE_UID"] = finding.resource_uid
                finding_dict["RESOURCE_NAME"] = finding.resource_name
                finding_dict["RESOURCE_DETAILS"] = finding.resource_details
                finding_dict["RESOURCE_TAGS"] = unroll_dict(finding.resource_tags)
                finding_dict["PARTITION"] = finding.partition
                finding_dict["REGION"] = finding.region
                finding_dict["DESCRIPTION"] = finding.metadata.Description
                finding_dict["RISK"] = finding.metadata.Risk
                finding_dict["RELATED_URL"] = finding.metadata.RelatedUrl
                finding_dict["REMEDIATION_RECOMMENDATION_TEXT"] = (
                    finding.metadata.Remediation.Recommendation.Text
                )
                finding_dict["REMEDIATION_RECOMMENDATION_URL"] = (
                    finding.metadata.Remediation.Recommendation.Url
                )
                finding_dict["REMEDIATION_CODE_NATIVEIAC"] = (
                    finding.metadata.Remediation.Code.NativeIaC
                )
                finding_dict["REMEDIATION_CODE_TERRAFORM"] = (
                    finding.metadata.Remediation.Code.Terraform
                )
                finding_dict["REMEDIATION_CODE_CLI"] = (
                    finding.metadata.Remediation.Code.CLI
                )
                finding_dict["REMEDIATION_CODE_OTHER"] = (
                    finding.metadata.Remediation.Code.Other
                )
                finding_dict["COMPLIANCE"] = unroll_dict(
                    finding.compliance, separator=": "
                )
                finding_dict["CATEGORIES"] = unroll_list(finding.metadata.Categories)
                finding_dict["DEPENDS_ON"] = unroll_list(finding.metadata.DependsOn)
                finding_dict["RELATED_TO"] = unroll_list(finding.metadata.RelatedTo)
                finding_dict["NOTES"] = finding.metadata.Notes
                finding_dict["PROWLER_VERSION"] = finding.prowler_version
                finding_dict["ADDITIONAL_URLS"] = unroll_list(
                    finding.metadata.AdditionalURLs
                )
                self._data.append(finding_dict)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Writes the findings to a file using the CSV format using the `Output._file_descriptor`."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=self._data[0].keys(),
                    delimiter=";",
                )
                if self._file_descriptor.tell() == 0:
                    csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(finding)
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
