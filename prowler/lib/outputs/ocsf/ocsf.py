import os
from typing import List

from py_ocsf_models.events.base_event import SeverityID, StatusID
from py_ocsf_models.events.findings.detection_finding import DetectionFinding
from py_ocsf_models.events.findings.detection_finding import (
    TypeID as DetectionFindingTypeID,
)
from py_ocsf_models.events.findings.finding import ActivityID, FindingInformation
from py_ocsf_models.objects.account import Account, TypeID
from py_ocsf_models.objects.cloud import Cloud
from py_ocsf_models.objects.group import Group
from py_ocsf_models.objects.metadata import Metadata
from py_ocsf_models.objects.organization import Organization
from py_ocsf_models.objects.product import Product
from py_ocsf_models.objects.remediation import Remediation
from py_ocsf_models.objects.resource_details import ResourceDetails

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.outputs.utils import unroll_dict_to_list


class OCSF(Output):
    """
    OCSF class that transforms the findings into the OCSF Detection Finding format.

    This class provides methods to transform the findings into the OCSF Detection Finding format and write them to a file.

    Attributes:
        - _data: A list to store the transformed findings.
        - _file_descriptor: A file descriptor to write the findings to a file.

    Methods:
        - transform(findings: List[Finding]) -> None: Transforms the findings into the OCSF Detection Finding format.
        - batch_write_data_to_file() -> None: Writes the findings to a file using the OCSF Detection Finding format using the `Output._file_descriptor`.
        - get_account_type_id_by_provider(provider: str) -> TypeID: Returns the TypeID based on the provider.
        - get_finding_status_id(muted: bool) -> StatusID: Returns the StatusID based on the muted value.

    References:
        - OCSF: https://schema.ocsf.io/1.2.0/classes/detection_finding
        - PY-OCSF-Model: https://github.com/prowler-cloud/py-ocsf-models
    """

    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into the OCSF format.

        Args:
            findings (List[Finding]): a list of Finding objects
        """
        try:
            for finding in findings:
                finding_activity = ActivityID.Create
                cloud_account_type = self.get_account_type_id_by_provider(
                    finding.metadata.Provider
                )
                finding_severity = getattr(
                    SeverityID,
                    finding.metadata.Severity.capitalize(),
                    SeverityID.Unknown,
                )
                finding_status = self.get_finding_status_id(finding.muted)

                detection_finding = DetectionFinding(
                    message=finding.status_extended,
                    activity_id=finding_activity.value,
                    activity_name=finding_activity.name,
                    finding_info=FindingInformation(
                        created_time_dt=finding.timestamp,
                        created_time=int(finding.timestamp.timestamp()),
                        desc=finding.metadata.Description,
                        title=finding.metadata.CheckTitle,
                        uid=finding.uid,
                        name=finding.resource_name,
                        product_uid="prowler",
                        types=finding.metadata.CheckType,
                    ),
                    time_dt=finding.timestamp,
                    time=int(finding.timestamp.timestamp()),
                    remediation=Remediation(
                        desc=finding.metadata.Remediation.Recommendation.Text,
                        references=list(
                            filter(
                                None,
                                [
                                    finding.metadata.Remediation.Code.NativeIaC,
                                    finding.metadata.Remediation.Code.Terraform,
                                    finding.metadata.Remediation.Code.CLI,
                                    finding.metadata.Remediation.Code.Other,
                                    finding.metadata.Remediation.Recommendation.Url,
                                ],
                            )
                        ),
                    ),
                    severity_id=finding_severity.value,
                    severity=finding_severity.name,
                    status_id=finding_status.value,
                    status=finding_status.name,
                    status_code=finding.status,
                    status_detail=finding.status_extended,
                    risk_details=finding.metadata.Risk,
                    resources=(
                        [
                            ResourceDetails(
                                labels=unroll_dict_to_list(finding.resource_tags),
                                name=finding.resource_name,
                                uid=finding.resource_uid,
                                group=Group(name=finding.metadata.ServiceName),
                                type=finding.metadata.ResourceType,
                                # TODO: this should be included only if using the Cloud profile
                                cloud_partition=finding.partition,
                                region=finding.region,
                                data={"details": finding.resource_details},
                            )
                        ]
                        if finding.metadata.Provider != "kubernetes"
                        else [
                            ResourceDetails(
                                labels=unroll_dict_to_list(finding.resource_tags),
                                name=finding.resource_name,
                                uid=finding.resource_uid,
                                group=Group(name=finding.metadata.ServiceName),
                                type=finding.metadata.ResourceType,
                                data={"details": finding.resource_details},
                                namespace=finding.region.replace("namespace: ", ""),
                            )
                        ]
                    ),
                    metadata=Metadata(
                        event_code=finding.metadata.CheckID,
                        product=Product(
                            uid="prowler",
                            name="Prowler",
                            vendor_name="Prowler",
                            version=finding.prowler_version,
                        ),
                        profiles=(
                            ["cloud", "datetime"]
                            if finding.metadata.Provider != "kubernetes"
                            else ["container", "datetime"]
                        ),
                        tenant_uid=finding.account_organization_uid,
                    ),
                    type_uid=DetectionFindingTypeID.Create,
                    type_name=f"Detection Finding: {DetectionFindingTypeID.Create.name}",
                    unmapped={
                        "related_url": finding.metadata.RelatedUrl,
                        "categories": finding.metadata.Categories,
                        "depends_on": finding.metadata.DependsOn,
                        "related_to": finding.metadata.RelatedTo,
                        "notes": finding.metadata.Notes,
                        "compliance": finding.compliance,
                    },
                )
                if finding.provider != "kubernetes":
                    detection_finding.cloud = Cloud(
                        account=Account(
                            name=finding.account_name,
                            type_id=cloud_account_type.value,
                            type=cloud_account_type.name.replace("_", " "),
                            uid=finding.account_uid,
                            labels=unroll_dict_to_list(finding.account_tags),
                        ),
                        org=Organization(
                            uid=finding.account_organization_uid,
                            name=finding.account_organization_name,
                            # TODO: add the org unit id and name
                        ),
                        provider=finding.provider,
                        region=finding.region,
                    )

                self._data.append(detection_finding)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Writes the findings to a file using the OCSF format using the `Output._file_descriptor`."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                self._file_descriptor.write("[")
                for finding in self._data:
                    self._file_descriptor.write(
                        finding.json(exclude_none=True, indent=4)
                    )
                    self._file_descriptor.write(",")
                if self._file_descriptor.tell() > 0:
                    if self._file_descriptor.tell() != 1:
                        self._file_descriptor.seek(
                            self._file_descriptor.tell() - 1, os.SEEK_SET
                        )
                    self._file_descriptor.truncate()
                    self._file_descriptor.write("]")
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def get_account_type_id_by_provider(provider: str) -> TypeID:
        """
        Returns the TypeID based on the provider.

        Args:
            provider (str): The provider name

        Returns:
            TypeID: The TypeID based on the provider
        """
        type_id = TypeID.Other
        if provider == "aws":
            type_id = TypeID.AWS_Account
        elif provider == "azure":
            type_id = TypeID.Azure_AD_Account
        elif provider == "gcp":
            type_id = TypeID.GCP_Account
        return type_id

    @staticmethod
    def get_finding_status_id(muted: bool) -> StatusID:
        """
        Returns the StatusID based on the muted value.

        Args:
            muted (bool): The muted value

        Returns:
            StatusID: The StatusID based on the muted value
        """
        status_id = StatusID.New
        if muted:
            status_id = StatusID.Suppressed
        return status_id
