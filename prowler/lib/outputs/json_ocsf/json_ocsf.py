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
from prowler.lib.outputs.common_models import FindingOutput


def get_account_type_id_by_provider(provider: str) -> TypeID:
    type_id = TypeID.Other
    if provider == "aws":
        type_id = TypeID.AWS_Account
    elif provider == "azure":
        type_id = TypeID.Azure_AD_Account
    elif provider == "gcp":
        type_id = TypeID.GCP_Account
    return type_id


def get_finding_status_id(status: str, muted: bool) -> StatusID:
    status_id = StatusID.Other
    if status == "FAIL":
        status_id = StatusID.New
    if muted:
        status_id = StatusID.Suppressed
    return status_id


def fill_json_ocsf(finding_output: FindingOutput) -> DetectionFinding:
    try:
        finding_activity = ActivityID.Create
        cloud_account_type = get_account_type_id_by_provider(finding_output.provider)
        finding_severity = getattr(
            SeverityID, finding_output.severity.capitalize(), SeverityID.Unknown
        )
        finding_status = get_finding_status_id(
            finding_output.status, finding_output.muted
        )

        detection_finding = DetectionFinding(
            activity_id=finding_activity.value,
            activity_name=finding_activity.name,
            finding_info=FindingInformation(
                created_time=finding_output.timestamp,
                desc=finding_output.description,
                title=finding_output.check_title,
                uid=finding_output.finding_uid,
                product_uid="prowler",
            ),
            event_time=finding_output.timestamp,
            remediation=Remediation(
                desc=finding_output.remediation_recommendation_text,
                references=list(
                    filter(
                        None,
                        [
                            finding_output.remediation_code_nativeiac,
                            finding_output.remediation_code_terraform,
                            finding_output.remediation_code_cli,
                            finding_output.remediation_code_other,
                            finding_output.remediation_recommendation_url,
                        ],
                    )
                ),
            ),
            severity_id=finding_severity.value,
            severity=finding_severity.name,
            status_id=finding_status.value,
            status=finding_status.name,
            status_code=finding_output.status,
            status_detail=finding_output.status_extended,
            risk_details=finding_output.risk,
            resources=[
                ResourceDetails(
                    # TODO: Check labels for other providers
                    labels=(
                        finding_output.resource_tags.split(",")
                        if finding_output.resource_tags
                        else []
                    ),
                    name=finding_output.resource_name,
                    uid=finding_output.resource_uid,
                    group=Group(name=finding_output.service_name),
                    type=finding_output.resource_type,
                    # TODO: this should be included only if using the Cloud profile
                    cloud_partition=finding_output.partition,
                    region=finding_output.region,
                    data={"details": finding_output.resource_details},
                )
            ],
            metadata=Metadata(
                event_code=finding_output.check_id,
                product=Product(
                    name="Prowler",
                    vendor_name="Prowler",
                    version=finding_output.prowler_version,
                ),
            ),
            type_uid=DetectionFindingTypeID.Create,
            type_name=DetectionFindingTypeID.Create.name,
            unmapped={
                "check_type": finding_output.check_type,
                "related_url": finding_output.related_url,
                "categories": finding_output.categories,
                "depends_on": finding_output.depends_on,
                "related_to": finding_output.related_to,
                "notes": finding_output.notes,
                "compliance": finding_output.compliance,
            },
        )

        if finding_output.provider == "kubernetes":
            detection_finding.container = (
                Container(
                    name=finding_output.resource_name,
                    uid=finding_output.resource_uid,
                ),
            )
            # TODO: Get the PID of the namespace (we only have the name of the namespace)
            # detection_finding.namespace_pid=,
        else:
            detection_finding.cloud = Cloud(
                account=Account(
                    name=finding_output.account_name,
                    type_id=cloud_account_type.value,
                    type=cloud_account_type.name,
                    uid=finding_output.account_uid,
                    labels=finding_output.account_tags,
                ),
                org=Organization(
                    uid=finding_output.account_organization_uid,
                    name=finding_output.account_organization_name,
                ),
                provider=finding_output.provider,
                region=finding_output.region,
            )

        return detection_finding

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
