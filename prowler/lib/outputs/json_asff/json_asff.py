from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.json_asff.models import (
    Compliance,
    ProductFields,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import hash_sha512


def generate_json_asff_status(status: str) -> str:
    json_asff_status = ""
    if status == "PASS":
        json_asff_status = "PASSED"
    elif status == "FAIL":
        json_asff_status = "FAILED"
    elif status == "MUTED":
        json_asff_status = "MUTED"
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


def fill_json_asff(finding_output, provider, finding, output_options):
    try:
        # Check if there are no resources in the finding
        if finding.resource_arn == "":
            if finding.resource_id == "":
                finding.resource_id = "NONE_PROVIDED"
            finding.resource_arn = finding.resource_id
        # The following line cannot be changed because it is the format we use to generate unique findings for AWS Security Hub
        # If changed some findings could be lost because the unique identifier will be different
        # TODO: get this from the provider output
        finding_output.Id = f"prowler-{finding.check_metadata.CheckID}-{provider.identity.account}-{finding.region}-{hash_sha512(finding.resource_id)}"
        finding_output.ProductArn = f"arn:{provider.identity.partition}:securityhub:{finding.region}::product/prowler/prowler"
        finding_output.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName=finding.resource_arn
        )
        finding_output.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        finding_output.AwsAccountId = provider.identity.account
        finding_output.Types = finding.check_metadata.CheckType
        finding_output.FirstObservedAt = finding_output.UpdatedAt = (
            finding_output.CreatedAt
        ) = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        finding_output.Severity = Severity(
            Label=finding.check_metadata.Severity.upper()
        )
        finding_output.Title = finding.check_metadata.CheckTitle
        # Description should NOT be longer than 1024 characters
        finding_output.Description = (
            (finding.status_extended[:1000] + "...")
            if len(finding.status_extended) > 1000
            else finding.status_extended
        )
        resource_tags = generate_json_asff_resource_tags(finding.resource_tags)
        finding_output.Resources = [
            Resource(
                Id=finding.resource_arn,
                Type=finding.check_metadata.ResourceType,
                Partition=provider.identity.partition,
                Region=finding.region,
                Tags=resource_tags,
            )
        ]
        # Iterate for each compliance framework
        compliance_summary = []
        associated_standards = []
        check_compliance = get_check_compliance(finding, "aws", output_options)
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
        finding_status = generate_json_asff_status(finding.status)

        finding_output.Compliance = Compliance(
            Status=finding_status,
            AssociatedStandards=associated_standards,
            RelatedRequirements=compliance_summary,
        )
        # Fill Recommendation Url if it is blank
        if not finding.check_metadata.Remediation.Recommendation.Url:
            finding.check_metadata.Remediation.Recommendation.Url = "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
        finding_output.Remediation = {
            "Recommendation": finding.check_metadata.Remediation.Recommendation
        }

        return finding_output
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
