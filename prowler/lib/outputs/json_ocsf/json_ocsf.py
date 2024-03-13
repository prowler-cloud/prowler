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

# from py_ocsf_models.objects.related_event import RelatedEvent
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


def fill_json_ocsf(finding_output: FindingOutput) -> DetectionFinding:
    try:
        # TODO: add or delete?
        # FindingInformation.created_time
        return DetectionFinding(
            activity_id=ActivityID.Create.value,
            activity_name=ActivityID.Create.name,
            finding_info=FindingInformation(
                desc=finding_output.description,
                title=finding_output.check_title,
                uid=finding_output.finding_uid,
                product_uid="prowler",
                # TODO: RelatedEvent and depends_on + related_to
                # related_events=[RelatedEvent()],
            ),
            cloud=Cloud(
                account=Account(
                    name=finding_output.account_name,
                    type_id=get_account_type_id_by_provider(
                        finding_output.provider
                    ).value,
                    type=get_account_type_id_by_provider(finding_output.provider).name,
                    uid=finding_output.account_uid,
                ),
                org=Organization(
                    uid=finding_output.account_organization_uid,
                    name=finding_output.account_organization_name,
                ),
                provider=finding_output.provider,
                region=finding_output.region,
            ),
            # TODO: Only fill the container object if it is Kubernetes
            container=Container(
                name=finding_output.resource_name,
                uid=finding_output.resource_uid,
            ),
            # TODO: Get the PID of the namespace (we only have the name of the namespace)
            # namespace_pid=finding_output.region,
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
            severity_id=getattr(
                SeverityID, finding_output.severity.capitalize(), SeverityID.Unknown
            ).value,
            severity=getattr(
                SeverityID, finding_output.severity.capitalize(), SeverityID.Unknown
            ).name,
            status_id=StatusID.Other.value,
            status=finding_output.status,
            status_detail=finding_output.status_extended,
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
                    cloud_partition=finding_output.partition,
                    region=finding_output.region,
                )
            ],
            metadata=Metadata(
                product=Product(
                    name="Prowler",
                    vendor_name="Prowler",
                    version=finding_output.prowler_version,
                ),
            ),
            type_id=DetectionFindingTypeID.Create,
            type_name=DetectionFindingTypeID.Create.name,
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
