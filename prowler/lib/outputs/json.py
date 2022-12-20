import os
import sys

from prowler.config.config import (
    json_asff_file_suffix,
    json_file_suffix,
    prowler_version,
    timestamp_utc,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.models import Compliance, ProductFields, Resource, Severity
from prowler.lib.utils.utils import hash_sha512, open_file


def fill_json_asff(finding_output, audit_info, finding):
    # Check if there are no resources in the finding
    if finding.resource_id == "":
        finding.resource_id = "NONE_PROVIDED"
    finding_output.Id = f"prowler-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{hash_sha512(finding.resource_id)}"
    finding_output.ProductArn = f"arn:{audit_info.audited_partition}:securityhub:{finding.region}::product/prowler/prowler"
    finding_output.ProductFields = ProductFields(
        ProviderVersion=prowler_version, ProwlerResourceName=finding.resource_id
    )
    finding_output.GeneratorId = "prowler-" + finding.check_metadata.CheckID
    finding_output.AwsAccountId = audit_info.audited_account
    finding_output.Types = finding.check_metadata.CheckType
    finding_output.FirstObservedAt = (
        finding_output.UpdatedAt
    ) = finding_output.CreatedAt = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    finding_output.Severity = Severity(Label=finding.check_metadata.Severity.upper())
    finding_output.Title = finding.check_metadata.CheckTitle
    finding_output.Description = finding.check_metadata.Description
    finding_output.Resources = [
        Resource(
            Id=finding.resource_id,
            Type=finding.check_metadata.ResourceType,
            Partition=audit_info.audited_partition,
            Region=finding.region,
        )
    ]
    # Check if any Requirement has > 64 characters
    check_types = []
    for type in finding.check_metadata.CheckType:
        check_types.extend(type.split("/"))
    # Add ED to PASS or FAIL (PASSED/FAILED)
    finding_output.Compliance = Compliance(
        Status=finding.status + "ED",
        RelatedRequirements=check_types,
    )
    finding_output.Remediation = {
        "Recommendation": finding.check_metadata.Remediation.Recommendation
    }

    return finding_output


def close_json(output_filename, output_directory, mode):
    try:
        suffix = json_file_suffix
        if mode == "json-asff":
            suffix = json_asff_file_suffix
        filename = f"{output_directory}/{output_filename}{suffix}"
        file_descriptor = open_file(
            filename,
            "a",
        )
        # Replace last comma for square bracket if not empty
        if file_descriptor.tell() > 0:
            file_descriptor.seek(file_descriptor.tell() - 1, os.SEEK_SET)
            file_descriptor.truncate()
            file_descriptor.write("]")
        file_descriptor.close()
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()
