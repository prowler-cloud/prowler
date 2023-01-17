import json
import sys

from colorama import Fore, Style

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance import fill_compliance
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.html import fill_html
from prowler.lib.outputs.json import fill_json_asff
from prowler.lib.outputs.models import (
    Check_Output_JSON_ASFF,
    generate_provider_output_csv,
    generate_provider_output_json,
)
from prowler.providers.aws.lib.allowlist.allowlist import is_allowlisted
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.security_hub.security_hub import send_to_security_hub
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


def stdout_report(finding, color, verbose, is_quiet):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.check_metadata.ServiceName

    if verbose:
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
                    # Check if --quiet to only add fails to outputs
                    if not (finding.status != "FAIL" and output_options.is_quiet):
                        # AWS specific outputs
                        if finding.check_metadata.Provider == "aws":
                            if (
                                "ens_rd2022_aws" in output_options.output_modes
                                or "cis" in str(output_options.output_modes)
                            ):
                                fill_compliance(
                                    output_options,
                                    finding,
                                    audit_info,
                                    file_descriptors,
                                )

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
                            if (
                                output_options.security_hub_enabled
                                and finding.status != "INFO"
                            ):
                                send_to_security_hub(
                                    output_options.is_quiet,
                                    finding.status,
                                    finding.region,
                                    finding_output,
                                    audit_info.audit_session,
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
            if output_options.verbose:
                print(f"\t{color}INFO{Style.RESET_ALL} There are no resources")
        # Separator between findings and bar
        if output_options.verbose:
            print()
        if file_descriptors:
            # Close all file descriptors
            for file_descriptor in file_descriptors:
                file_descriptors.get(file_descriptor).close()
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


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
        filename = ""
        # Get only last part of the path
        if output_mode == "csv":
            filename = f"{output_filename}{csv_file_suffix}"
        elif output_mode == "json":
            filename = f"{output_filename}{json_file_suffix}"
        elif output_mode == "json-asff":
            filename = f"{output_filename}{json_asff_file_suffix}"
        elif output_mode == "html":
            filename = f"{output_filename}{html_file_suffix}"
        logger.info(f"Sending outputs to S3 bucket {output_bucket}")
        bucket_remote_dir = output_directory.split("/")[-1]
        file_name = output_directory + "/" + filename
        bucket_name = output_bucket
        object_name = bucket_remote_dir + "/" + output_mode + "/" + filename
        s3_client = audit_session.client("s3")
        s3_client.upload_file(file_name, bucket_name, object_name)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()


def extract_findings_statistics(findings: list) -> dict:
    """
    extract_findings_statistics takes a list of findings and returns the following dict with the aggregated statistics
    {
        "total_pass": 0,
        "total_fail": 0,
        "resources_count": 0,
        "findings_count": 0,
    }
    """
    logger.info("Extracting audit statistics...")
    stats = {}
    total_pass = 0
    total_fail = 0
    resources = set()
    findings_count = 0

    for finding in findings:
        # Save the resource_id
        resources.add(finding.resource_id)
        if finding.status == "PASS":
            total_pass += 1
            findings_count += 1
        if finding.status == "FAIL":
            total_fail += 1
            findings_count += 1

    stats["total_pass"] = total_pass
    stats["total_fail"] = total_fail
    stats["resources_count"] = len(resources)
    stats["findings_count"] = findings_count

    return stats
