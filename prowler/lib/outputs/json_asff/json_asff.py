from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.json_asff.models import (
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Recommendation,
    Remediation,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import hash_sha512


def generate_json_asff_status(status: str, muted: bool = False) -> str:
    json_asff_status = ""
    if muted:
        # Per AWS Security Hub "MUTED" is not a valid status
        # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
        json_asff_status = "WARNING"
    else:
        if status == "PASS":
            json_asff_status = "PASSED"
        elif status == "FAIL":
            json_asff_status = "FAILED"
        else:
            json_asff_status = "NOT_AVAILABLE"

    return json_asff_status


def generate_json_asff_resource_tags(tags):
    try:
        resource_tags = {}
        if tags and tags != [None]:
            for tag in tags:
                if "Key" in tag and "Value" in tag:
                    resource_tags[tag["Key"]] = tag["Value"]
                else:
                    resource_tags.update(tag)
            if len(resource_tags) == 0:
                return None
        else:
            return None
        return resource_tags
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def fill_json_asff(provider, finding):
    """
    Fill the finding's output in JSON ASFF format.

    Parameters:
    - provider: The provider object containing information about the provider (e.g., AWS) and the output options object containing information about the desired output format.
    - finding: The finding object containing information about the specific finding.

    Returns:
    - finding_output: The filled finding's output in JSON ASFF format.
    """

    try:
        # Check if there are no resources in the finding
        if finding.resource_arn == "":
            if finding.resource_id == "":
                finding.resource_id = "NONE_PROVIDED"
            finding.resource_arn = finding.resource_id

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        resource_tags = generate_json_asff_resource_tags(finding.resource_tags)

        # Iterate for each compliance framework
        compliance_summary = []
        associated_standards = []
        check_compliance = get_check_compliance(
            finding, provider.type, provider.output_options
        )
        for key, value in check_compliance.items():
            if (
                len(associated_standards) < 20
            ):  # AssociatedStandards should NOT have more than 20 items
                associated_standards.append({"StandardsId": key})
                item = f"{key} {' '.join(value)}"
                if len(item) > 64:
                    item = item[0:63]
                compliance_summary.append(item)

        # Ensures finding_status matches allowed values in ASFF
        finding_status = generate_json_asff_status(finding.status, finding.muted)

        json_asff_output = Check_Output_JSON_ASFF(
            # The following line cannot be changed because it is the format we use to generate unique findings for AWS Security Hub
            # If changed some findings could be lost because the unique identifier will be different
            # TODO: get this from the provider output
            Id=f"prowler-{finding.check_metadata.CheckID}-{provider.identity.account}-{finding.region}-{hash_sha512(finding.resource_id)}",
            ProductArn=f"arn:{provider.identity.partition}:securityhub:{finding.region}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProwlerResourceName=finding.resource_arn,
            ),
            GeneratorId="prowler-" + finding.check_metadata.CheckID,
            AwsAccountId=provider.identity.account,
            Types=finding.check_metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.check_metadata.Severity.upper()),
            Title=finding.check_metadata.CheckTitle,
            Description=finding.status_extended,
            Resources=[
                Resource(
                    Id=finding.resource_arn,
                    Type=finding.check_metadata.ResourceType,
                    Partition=provider.identity.partition,
                    Region=finding.region,
                    Tags=resource_tags,
                )
            ],
            Compliance=Compliance(
                Status=finding_status,
                AssociatedStandards=associated_standards,
                RelatedRequirements=compliance_summary,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.check_metadata.Remediation.Recommendation.Text,
                    Url=finding.check_metadata.Remediation.Recommendation.Url,
                )
            ),
        )
        return json_asff_output
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
