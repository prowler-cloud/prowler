from py_ocsf_models.events.base_event import SeverityID, StatusID
from py_ocsf_models.events.findings.detection_finding import DetectionFinding
from py_ocsf_models.events.findings.finding import ActivityID, FindingInformation
from py_ocsf_models.objects.account import Account, TypeID
from py_ocsf_models.objects.group import Group
from py_ocsf_models.objects.metadata import Metadata
from py_ocsf_models.objects.organization import Organization
from py_ocsf_models.objects.product import Product
from py_ocsf_models.objects.remediation import Remediation
from py_ocsf_models.objects.resource_details import ResourceDetails
from py_ocsf_models.profiles.cloud import Cloud, CloudProfile

from prowler.lib.logger import logger

# from py_ocsf_models.objects.related_event import RelatedEvent
from prowler.lib.outputs.common_models import FindingOutput


# TODO: output_options lives within the provider
# provider_data should be a type
# Merge this two objects
def fill_json_ocsf(finding_output: FindingOutput) -> DetectionFinding:
    try:
        # TODO:
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
            # TODO: cloud can't be a CloudProfile with a Cloud object within, needs to be one level above
            cloud=CloudProfile(
                cloud=Cloud(
                    # TODO: function to get this by provider
                    account=Account(
                        name=finding_output.account_name,
                        # TODO: function to get this type based on the provider
                        type_id=TypeID.AWS_Account.value,
                        type=TypeID.AWS_Account.name,
                        uid=finding_output.account_uid,
                    ),
                    # TODO: function to get this by provider
                    org=Organization(
                        uid=finding_output.account_organization_uid,
                        name=finding_output.account_organization,
                        # TODO: remove this once the fixes are released in the models lib
                        ou_name="",
                    ),
                    provider=finding_output.provider,
                    region=finding_output.region,
                )
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
            severity_id=getattr(
                SeverityID, finding_output.severity.capitalize(), SeverityID.Unknown
            ).value,
            severity=getattr(
                SeverityID, finding_output.severity.capitalize(), SeverityID.Unknown
            ).name,
            status_id=StatusID.Other.value,
            status=finding_output.status,
            status_detail=finding_output.status_extended,
            # TODO: pending to add cloud_partition and region
            # Check labels for other providers
            resources=[
                ResourceDetails(
                    labels=(
                        finding_output.resource_tags.split(",")
                        if finding_output.resource_tags
                        else []
                    ),
                    name=finding_output.resource_name,
                    uid=finding_output.resource_uid,
                    # TODO: remove uid once the fixes are released in the models lib
                    group=Group(name=finding_output.service_name, uid=""),
                    type=finding_output.resource_type,
                )
            ],
            # TODO: remove version once the fixes are released in the models lib
            # Also Product name and uid, only vendor name needed
            metadata=Metadata(
                product=Product(
                    name="Prowler",
                    vendor_name="Prowler",
                    uid="",
                    version=finding_output.prowler_version,
                ),
                version="1.1.0",
            ),
            # TODO: add values from DetectionFinding TypeID once the fixes are released in the models lib
            # TODO: add compliance object, check if there is another compliance finding
            type_id=200401,
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def generate_json_ocsf_status(status: str):
    json_ocsf_status = ""
    if status == "PASS":
        json_ocsf_status = "Success"
    elif status == "FAIL":
        json_ocsf_status = "Failure"
    elif status == "MUTED":
        json_ocsf_status = "Other"
    else:
        json_ocsf_status = "Unknown"

    return json_ocsf_status


def generate_json_ocsf_status_id(status: str):
    json_ocsf_status_id = 0
    if status == "PASS":
        json_ocsf_status_id = 1
    elif status == "FAIL":
        json_ocsf_status_id = 2
    elif status == "MUTED":
        json_ocsf_status_id = 99
    else:
        json_ocsf_status_id = 0

    return json_ocsf_status_id


def generate_json_ocsf_severity_id(severity: str):
    json_ocsf_severity_id = 0
    if severity == "low":
        json_ocsf_severity_id = 2
    elif severity == "medium":
        json_ocsf_severity_id = 3
    elif severity == "high":
        json_ocsf_severity_id = 4
    elif severity == "critical":
        json_ocsf_severity_id = 5

    return json_ocsf_severity_id
