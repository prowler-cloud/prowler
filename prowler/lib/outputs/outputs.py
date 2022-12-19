import json
import sys
from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from colorama import Fore, Style

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    timestamp,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.csv import generate_csv_fields
from prowler.lib.outputs.html import add_html_header, fill_html
from prowler.lib.outputs.json import fill_json_asff
from prowler.lib.outputs.models import (
    Aws_Check_Output_CSV,
    Azure_Check_Output_CSV,
    Check_Output_CSV_CIS,
    Check_Output_CSV_ENS_RD2022,
    Check_Output_JSON_ASFF,
)
from prowler.lib.utils.utils import file_exists, open_file
from prowler.providers.aws.lib.allowlist.allowlist import is_allowlisted
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.security_hub.security_hub import send_to_security_hub
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


def stdout_report(finding, color, verbose, is_quiet):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.check_metadata.ServiceName

    if is_quiet and "FAIL" in finding.status:
        print(
            f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
        )
    elif not is_quiet and verbose:
        print(
            f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
        )


def report(check_findings, output_options, audit_info):
    try:
        # TO-DO Generic Function
        if isinstance(audit_info, AWS_Audit_Info):
            check_findings.sort(key=lambda x: x.region)

        if isinstance(audit_info, Azure_Audit_Info):
            check_findings.sort(key=lambda x: x.subscription)

        # Generate the required output files
        file_descriptors = {}
        if output_options.output_modes:
            # if isinstance(audit_info, AWS_Audit_Info):
            # We have to create the required output files
            file_descriptors = fill_file_descriptors(
                output_options.output_modes,
                output_options.output_directory,
                output_options.output_filename,
                audit_info,
            )

        if check_findings:
            for finding in check_findings:
                # Check if finding is allowlisted
                if output_options.allowlist_file:
                    if is_allowlisted(
                        output_options.allowlist_file,
                        audit_info.audited_account,
                        finding.check_metadata.CheckID,
                        finding.region,
                        finding.resource_id,
                    ):
                        finding.status = "WARNING"
                # Print findings by stdout
                color = set_report_color(finding.status)
                stdout_report(
                    finding, color, output_options.verbose, output_options.is_quiet
                )

                if file_descriptors:
                    # AWS specific outputs
                    if finding.check_metadata.Provider == "aws":
                        if "ens_rd2022_aws" in output_options.output_modes:
                            # We have to retrieve all the check's compliance requirements
                            check_compliance = output_options.bulk_checks_metadata[
                                finding.check_metadata.CheckID
                            ].Compliance
                            for compliance in check_compliance:
                                if (
                                    compliance.Framework == "ENS"
                                    and compliance.Version == "RD2022"
                                ):
                                    for requirement in compliance.Requirements:
                                        requirement_description = (
                                            requirement.Description
                                        )
                                        requirement_id = requirement.Id
                                        for attribute in requirement.Attributes:
                                            compliance_row = Check_Output_CSV_ENS_RD2022(
                                                Provider=finding.check_metadata.Provider,
                                                AccountId=audit_info.audited_account,
                                                Region=finding.region,
                                                AssessmentDate=timestamp.isoformat(),
                                                Requirements_Id=requirement_id,
                                                Requirements_Description=requirement_description,
                                                Requirements_Attributes_IdGrupoControl=attribute.get(
                                                    "IdGrupoControl"
                                                ),
                                                Requirements_Attributes_Marco=attribute.get(
                                                    "Marco"
                                                ),
                                                Requirements_Attributes_Categoria=attribute.get(
                                                    "Categoria"
                                                ),
                                                Requirements_Attributes_DescripcionControl=attribute.get(
                                                    "DescripcionControl"
                                                ),
                                                Requirements_Attributes_Nivel=attribute.get(
                                                    "Nivel"
                                                ),
                                                Requirements_Attributes_Tipo=attribute.get(
                                                    "Tipo"
                                                ),
                                                Requirements_Attributes_Dimensiones=",".join(
                                                    attribute.get("Dimensiones")
                                                ),
                                                Status=finding.status,
                                                StatusExtended=finding.status_extended,
                                                ResourceId=finding.resource_id,
                                                CheckId=finding.check_metadata.CheckID,
                                            )

                                    csv_header = generate_csv_fields(
                                        Check_Output_CSV_ENS_RD2022
                                    )
                                    csv_writer = DictWriter(
                                        file_descriptors["ens_rd2022_aws"],
                                        fieldnames=csv_header,
                                        delimiter=";",
                                    )
                                    csv_writer.writerow(compliance_row.__dict__)
                        elif "cis" in str(output_options.output_modes):
                            # We have to retrieve all the check's compliance requirements
                            check_compliance = output_options.bulk_checks_metadata[
                                finding.check_metadata.CheckID
                            ].Compliance
                            for compliance in check_compliance:
                                if compliance.Framework == "CIS-AWS":
                                    for requirement in compliance.Requirements:
                                        requirement_description = (
                                            requirement.Description
                                        )
                                        requirement_id = requirement.Id
                                        for attribute in requirement.Attributes:
                                            compliance_row = Check_Output_CSV_CIS(
                                                Provider=finding.check_metadata.Provider,
                                                AccountId=audit_info.audited_account,
                                                Region=finding.region,
                                                AssessmentDate=timestamp.isoformat(),
                                                Requirements_Id=requirement_id,
                                                Requirements_Description=requirement_description,
                                                Requirements_Attributes_Section=attribute.get(
                                                    "Section"
                                                ),
                                                Requirements_Attributes_Profile=attribute.get(
                                                    "Profile"
                                                ),
                                                Requirements_Attributes_AssessmentStatus=attribute.get(
                                                    "AssessmentStatus"
                                                ),
                                                Requirements_Attributes_Description=attribute.get(
                                                    "Description"
                                                ),
                                                Requirements_Attributes_RationaleStatement=attribute.get(
                                                    "RationaleStatement"
                                                ),
                                                Requirements_Attributes_ImpactStatement=attribute.get(
                                                    "ImpactStatement"
                                                ),
                                                Requirements_Attributes_RemediationProcedure=attribute.get(
                                                    "RemediationProcedure"
                                                ),
                                                Requirements_Attributes_AuditProcedure=attribute.get(
                                                    "AuditProcedure"
                                                ),
                                                Requirements_Attributes_AdditionalInformation=attribute.get(
                                                    "AdditionalInformation"
                                                ),
                                                Requirements_Attributes_References=attribute.get(
                                                    "References"
                                                ),
                                                Status=finding.status,
                                                StatusExtended=finding.status_extended,
                                                ResourceId=finding.resource_id,
                                                CheckId=finding.check_metadata.CheckID,
                                            )

                                    csv_header = generate_csv_fields(
                                        Check_Output_CSV_CIS
                                    )
                                    csv_writer = DictWriter(
                                        file_descriptors[
                                            output_options.output_modes[-1]
                                        ],
                                        fieldnames=csv_header,
                                        delimiter=";",
                                    )
                                    csv_writer.writerow(compliance_row.__dict__)

                        if "html" in file_descriptors:
                            fill_html(file_descriptors["html"], finding)

                        file_descriptors["html"].write("")

                        if "json-asff" in file_descriptors:
                            finding_output = Check_Output_JSON_ASFF()
                            fill_json_asff(finding_output, audit_info, finding)

                            json.dump(
                                finding_output.dict(),
                                file_descriptors["json-asff"],
                                indent=4,
                            )
                            file_descriptors["json-asff"].write(",")

                        # Check if it is needed to send findings to security hub
                        if output_options.security_hub_enabled:
                            send_to_security_hub(
                                finding.region, finding_output, audit_info.audit_session
                            )

                    # Common outputs
                    if "csv" in file_descriptors:
                        csv_writer, finding_output = generate_provider_output_csv(
                            finding.check_metadata.Provider,
                            finding,
                            audit_info,
                            "csv",
                            file_descriptors["csv"],
                        )
                        csv_writer.writerow(finding_output.__dict__)

                    if "json" in file_descriptors:
                        finding_output = generate_provider_output_json(
                            finding.check_metadata.Provider,
                            finding,
                            audit_info,
                            "json",
                            file_descriptors["json"],
                        )
                        json.dump(
                            finding_output.dict(),
                            file_descriptors["json"],
                            indent=4,
                        )
                        file_descriptors["json"].write(",")

        else:  # No service resources in the whole account
            color = set_report_color("INFO")
            if not output_options.is_quiet and output_options.verbose:
                print(f"\t{color}INFO{Style.RESET_ALL} There are no resources")
        # Separator between findings and bar
        if output_options.is_quiet or output_options.verbose:
            print()
        if file_descriptors:
            # Close all file descriptors
            for file_descriptor in file_descriptors:
                file_descriptors.get(file_descriptor).close()
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def initialize_file_descriptor(
    filename: str,
    output_mode: str,
    audit_info: AWS_Audit_Info,
    format: Any = None,
) -> TextIOWrapper:
    """Open/Create the output file. If needed include headers or the required format"""
    try:
        if file_exists(filename):
            file_descriptor = open_file(
                filename,
                "a",
            )
        else:
            file_descriptor = open_file(
                filename,
                "a",
            )

            if output_mode in ("csv", "ens_rd2022_aws", "cis_1.5_aws", "cis_1.4_aws"):
                # Format is the class model of the CSV format to print the headers
                csv_header = [x.upper() for x in generate_csv_fields(format)]
                csv_writer = DictWriter(
                    file_descriptor, fieldnames=csv_header, delimiter=";"
                )
                csv_writer.writeheader()

            if output_mode in ("json", "json-asff"):
                file_descriptor.write("[")
            if "html" in output_mode:
                add_html_header(file_descriptor, audit_info)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptor


def fill_file_descriptors(output_modes, output_directory, output_filename, audit_info):
    try:
        file_descriptors = {}
        if output_modes:
            for output_mode in output_modes:
                if output_mode == "csv":
                    filename = f"{output_directory}/{output_filename}{csv_file_suffix}"
                    if isinstance(audit_info, AWS_Audit_Info):
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Aws_Check_Output_CSV,
                        )
                    if isinstance(audit_info, Azure_Audit_Info):
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Azure_Check_Output_CSV,
                        )
                    file_descriptors.update({output_mode: file_descriptor})

                if output_mode == "json":
                    filename = f"{output_directory}/{output_filename}{json_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename, output_mode, audit_info
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                if isinstance(audit_info, AWS_Audit_Info):

                    if output_mode == "json-asff":
                        filename = f"{output_directory}/{output_filename}{json_asff_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "html":
                        filename = (
                            f"{output_directory}/{output_filename}{html_file_suffix}"
                        )
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "ens_rd2022_aws":
                        filename = f"{output_directory}/{output_filename}_ens_rd2022_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Check_Output_CSV_ENS_RD2022,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "cis_1.5_aws":
                        filename = f"{output_directory}/{output_filename}_cis_1.5_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info, Check_Output_CSV_CIS
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "cis_1.4_aws":
                        filename = f"{output_directory}/{output_filename}_cis_1.4_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info, Check_Output_CSV_CIS
                        )
                        file_descriptors.update({output_mode: file_descriptor})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptors


def set_report_color(status: str) -> str:
    """Return the color for a give result status"""
    color = ""
    if status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "ERROR":
        color = Fore.BLACK
    elif status == "WARNING":
        color = orange_color
    elif status == "INFO":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL, ERROR or WARNING")
    return color


def send_to_s3_bucket(
    output_filename, output_directory, output_mode, output_bucket, audit_session
):
    try:
        # Get only last part of the path
        if output_mode == "csv":
            filename = f"{output_filename}{csv_file_suffix}"
        elif output_mode == "json":
            filename = f"{output_filename}{json_file_suffix}"
        elif output_mode == "json-asff":
            filename = f"{output_filename}{json_asff_file_suffix}"
        logger.info(f"Sending outputs to S3 bucket {output_bucket}")
        file_name = output_directory + "/" + filename
        bucket_name = output_bucket
        object_name = output_directory + "/" + output_mode + "/" + filename
        s3_client = audit_session.client("s3")
        s3_client.upload_file(file_name, bucket_name, object_name)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()

def extract_findings_statistics(findings: list) -> dict:
    stats = {}
    total_pass = 0
    total_fail = 0
    resources = set()
    findings_count = 0

    for finding in findings:
        # Save the resource_id
        resources.add(finding.resource_id)
        # Increment findings
        findings_count += 1
        if finding.status == "PASS":
            total_pass += 1
        if finding.status == "FAIL":
            total_fail += 1

    stats["total_pass"] = total_pass
    stats["total_fail"] = total_fail
    stats["resources_count"] = len(resources)
    stats["findings_count"] = findings_count

    return stats

