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
from py_ocsf_models.objects.container import Container
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
        - get_finding_status_id(status: str, muted: bool) -> StatusID: Returns the StatusID based on the status and muted values.

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
                    finding.provider
                )
                finding_severity = getattr(
                    SeverityID, finding.severity.capitalize(), SeverityID.Unknown
                )
                finding_status = self.get_finding_status_id(
                    finding.status, finding.muted
                )

                detection_finding = DetectionFinding(
                    activity_id=finding_activity.value,
                    activity_name=finding_activity.name,
                    finding_info=FindingInformation(
                        created_time=finding.timestamp,
                        desc=finding.description,
                        title=finding.check_title,
                        uid=finding.finding_uid,
                        product_uid="prowler",
                    ),
                    event_time=finding.timestamp,
                    remediation=Remediation(
                        desc=finding.remediation_recommendation_text,
                        references=list(
                            filter(
                                None,
                                [
                                    finding.remediation_code_nativeiac,
                                    finding.remediation_code_terraform,
                                    finding.remediation_code_cli,
                                    finding.remediation_code_other,
                                    finding.remediation_recommendation_url,
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
                    risk_details=finding.risk,
                    resources=[
                        ResourceDetails(
                            labels=unroll_dict_to_list(finding.resource_tags),
                            name=finding.resource_name,
                            uid=finding.resource_uid,
                            group=Group(name=finding.service_name),
                            type=finding.resource_type,
                            # TODO: this should be included only if using the Cloud profile
                            cloud_partition=finding.partition,
                            region=finding.region,
                            data={"details": finding.resource_details},
                        )
                    ],
                    metadata=Metadata(
                        event_code=finding.check_id,
                        product=Product(
                            name="Prowler",
                            vendor_name="Prowler",
                            version=finding.prowler_version,
                        ),
                    ),
                    type_uid=DetectionFindingTypeID.Create,
                    type_name=DetectionFindingTypeID.Create.name,
                    unmapped={
                        "check_type": finding.check_type,
                        "related_url": finding.related_url,
                        "categories": finding.categories,
                        "depends_on": finding.depends_on,
                        "related_to": finding.related_to,
                        "notes": finding.notes,
                        "compliance": finding.compliance,
                    },
                )

                if finding.provider == "kubernetes":
                    detection_finding.container = Container(
                        name=finding.resource_name,
                        uid=finding.resource_uid,
                    )
                    # TODO: Get the PID of the namespace (we only have the name of the namespace)
                    # detection_finding.namespace_pid=,
                else:
                    detection_finding.cloud = Cloud(
                        account=Account(
                            name=finding.account_name,
                            type_id=cloud_account_type.value,
                            type=cloud_account_type.name,
                            uid=finding.account_uid,
                            labels=unroll_dict_to_list(finding.account_tags),
                        ),
                        org=Organization(
                            uid=finding.account_organization_uid,
                            name=finding.account_organization_name,
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
    def get_finding_status_id(status: str, muted: bool) -> StatusID:
        """
        Returns the StatusID based on the status and muted values.

        Args:
            status (str): The status value
            muted (bool): The muted value

        Returns:
            StatusID: The StatusID based on the status and muted values
        """
        status_id = StatusID.Other
        if status == "FAIL":
            status_id = StatusID.New
        if muted:
            status_id = StatusID.Suppressed
        return status_id
