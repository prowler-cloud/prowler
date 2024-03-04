import os
import sys

from prowler.config.config import (
    json_asff_file_suffix,
    json_file_suffix,
    json_ocsf_file_suffix,
    prowler_version,
    timestamp,
    timestamp_utc,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.models import (
    Account,
    Check_Output_JSON_OCSF,
    Cloud,
    Compliance,
    Compliance_OCSF,
    Feature,
    Finding,
    Group,
    Metadata,
    Organization,
    Product,
    ProductFields,
    Remediation_OCSF,
    Resource,
    Resources,
    Severity,
    get_check_compliance,
    unroll_dict_to_list,
)
from prowler.lib.utils.utils import hash_sha512, open_file, outputs_unix_timestamp


def fill_json_asff(finding_output, audit_info, finding, output_options):
    try:
        # Check if there are no resources in the finding
        if finding.resource_arn == "":
            if finding.resource_id == "":
                finding.resource_id = "NONE_PROVIDED"
            finding.resource_arn = finding.resource_id
        # The following line cannot be changed because it is the format we use to generate unique findings for AWS Security Hub
        # If changed some findings could be lost because the unique identifier will be different
        finding_output.Id = f"prowler-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{hash_sha512(finding.resource_id)}"
        finding_output.ProductArn = f"arn:{audit_info.audited_partition}:securityhub:{finding.region}::product/prowler/prowler"
        finding_output.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName=finding.resource_arn
        )
        finding_output.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        finding_output.AwsAccountId = audit_info.audited_account
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
                Partition=audit_info.audited_partition,
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


def fill_json_ocsf(provider, finding, output_options) -> Check_Output_JSON_OCSF:
    try:
        resource_region = ""
        resource_name = ""
        resource_uid = ""
        finding_uid = ""
        project_uid = ""
        resource_labels = finding.resource_tags if finding.resource_tags else []
        aws_account_name = ""
        aws_org_uid = ""
        account = None
        org = None
        profile = ""
        if provider.type == "aws":
            profile = (
                provider.identity.profile
                if provider.identity.profile is not None
                else "default"
            )
        if (
            hasattr(provider, "organizations_metadata")
            and provider.organizations_metadata
        ):
            aws_account_name = provider.organizations_metadata.account_details_name
            aws_org_uid = provider.organizations_metadata.account_details_org
        if finding.check_metadata.Provider == "aws":
            account = Account(
                name=aws_account_name,
                uid=provider.identity.account,
            )
            org = Organization(
                name=aws_org_uid,
                uid=aws_org_uid,
            )
            resource_region = finding.region
            resource_name = finding.resource_id
            resource_uid = finding.resource_arn
            finding_uid = f"prowler-{finding.check_metadata.Provider}-{finding.check_metadata.CheckID}-{provider.identity.account}-{finding.region}-{finding.resource_id}"
        elif finding.check_metadata.Provider == "azure":
            account = Account(
                name=finding.subscription,
                uid=finding.subscription,
            )
            org = Organization(
                name=provider.identity.domain,
                uid=provider.identity.domain,
            )
            resource_name = finding.resource_name
            resource_uid = finding.resource_id
            finding_uid = f"prowler-{finding.check_metadata.Provider}-{finding.check_metadata.CheckID}-{finding.subscription}-{finding.resource_id}"
        elif finding.check_metadata.Provider == "gcp":
            project_uid = finding.project_id
            resource_region = finding.location.lower()
            resource_name = finding.resource_name
            resource_uid = finding.resource_id
            finding_uid = f"prowler-{finding.check_metadata.Provider}-{finding.check_metadata.CheckID}-{finding.project_id}-{finding.resource_id}"
        cloud = Cloud(
            provider=finding.check_metadata.Provider,
            org=org,
            account=account,
            region=resource_region,
            project_uid=project_uid,
        )
        finding_ocsf = Finding(
            title=finding.check_metadata.CheckTitle,
            uid=finding_uid,
            desc=finding.check_metadata.Description,
            supporting_data={
                "Risk": finding.check_metadata.Risk,
                "Notes": finding.check_metadata.Notes,
            },
            related_events=finding.check_metadata.DependsOn
            + finding.check_metadata.RelatedTo,
            remediation=Remediation_OCSF(
                kb_articles=list(
                    filter(
                        None,
                        [
                            finding.check_metadata.Remediation.Code.NativeIaC,
                            finding.check_metadata.Remediation.Code.Terraform,
                            finding.check_metadata.Remediation.Code.CLI,
                            finding.check_metadata.Remediation.Code.Other,
                            finding.check_metadata.Remediation.Recommendation.Url,
                        ],
                    )
                ),
                desc=finding.check_metadata.Remediation.Recommendation.Text,
            ),
            types=finding.check_metadata.CheckType,
            src_url=finding.check_metadata.RelatedUrl,
        )
        resources = []
        resources.append(
            Resources(
                group=Group(name=finding.check_metadata.ServiceName),
                region=resource_region,
                name=resource_name,
                labels=resource_labels,
                uid=resource_uid,
                type=finding.check_metadata.ResourceType,
                details=finding.resource_details,
            )
        )
        metadata = Metadata(
            product=Product(
                feature=Feature(
                    uid=finding.check_metadata.CheckID,
                    name=finding.check_metadata.CheckID,
                )
            ),
            original_time=outputs_unix_timestamp(
                output_options.unix_timestamp, timestamp
            ),
            profiles=[profile],
        )
        compliance = Compliance_OCSF(
            status=generate_json_ocsf_status(finding.status),
            status_detail=finding.status_extended,
            requirements=unroll_dict_to_list(
                get_check_compliance(
                    finding, finding.check_metadata.Provider, output_options
                )
            ),
        )
        finding_output = Check_Output_JSON_OCSF(
            finding=finding_ocsf,
            resources=resources,
            status_detail=finding.status_extended,
            message=finding.status_extended,
            severity=finding.check_metadata.Severity.capitalize(),
            severity_id=generate_json_ocsf_severity_id(finding.check_metadata.Severity),
            status=generate_json_ocsf_status(finding.status),
            status_id=generate_json_ocsf_status_id(finding.status),
            compliance=compliance,
            cloud=cloud,
            time=outputs_unix_timestamp(output_options.unix_timestamp, timestamp),
            metadata=metadata,
        )
        return finding_output
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


def close_json(output_filename, output_directory, mode):
    """close_json closes the output JSON file replacing the last comma with ]"""
    try:
        suffix = json_file_suffix
        if mode == "json-asff":
            suffix = json_asff_file_suffix
        elif mode == "json-ocsf":
            suffix = json_ocsf_file_suffix
        filename = f"{output_directory}/{output_filename}{suffix}"
        # Close JSON file if exists
        if os.path.isfile(filename):
            file_descriptor = open_file(
                filename,
                "a",
            )
            # Replace last comma for square bracket if not empty
            if file_descriptor.tell() > 0:
                if file_descriptor.tell() != 1:
                    file_descriptor.seek(file_descriptor.tell() - 1, os.SEEK_SET)
                file_descriptor.truncate()
                file_descriptor.write("]")
            file_descriptor.close()
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)
