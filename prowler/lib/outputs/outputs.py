import json
from csv import DictWriter

from colorama import Fore, Style

from prowler.config.config import available_compliance_frameworks, orange_color
from prowler.lib.logger import logger
from prowler.lib.outputs.common import (
    fill_common_finding_data,
    generate_provider_output,
    get_provider_data_mapping,
)
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.compliance.compliance import (
    add_manual_controls,
    fill_compliance,
    get_check_compliance,
)
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.html.html import fill_html
from prowler.lib.outputs.json_asff.json_asff import fill_json_asff
from prowler.lib.outputs.json_ocsf.json_ocsf import fill_json_ocsf
from prowler.lib.outputs.utils import unroll_dict, unroll_list


def stdout_report(finding, color, verbose, status, fix):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.check_metadata.ServiceName
    if finding.check_metadata.Provider == "gcp":
        details = finding.location.lower()
    if finding.check_metadata.Provider == "kubernetes":
        details = finding.namespace.lower()

    if (verbose or fix) and (not status or finding.status in status):
        if finding.muted:
            print(
                f"\t{color}MUTED ({finding.status}){Style.RESET_ALL} {details}: {finding.status_extended}"
            )
        else:
            print(
                f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
            )


def report(check_findings, provider):
    try:
        output_options = provider.output_options
        file_descriptors = {}
        if check_findings:
            # TO-DO Generic Function
            if provider.type == "aws":
                check_findings.sort(key=lambda x: x.region)

            if provider.type == "azure":
                check_findings.sort(key=lambda x: x.subscription)

            # Generate the required output files
            if output_options.output_modes and not output_options.fixer:
                # We have to create the required output files
                file_descriptors = fill_file_descriptors(
                    output_options.output_modes,
                    output_options.output_directory,
                    output_options.output_filename,
                    provider,
                )

            for finding in check_findings:
                # Print findings by stdout
                color = set_report_color(finding.status, finding.muted)
                stdout_report(
                    finding,
                    color,
                    output_options.verbose,
                    output_options.status,
                    output_options.fixer,
                )

                if file_descriptors:
                    # Check if --status is enabled and if the filter applies
                    if (
                        not output_options.status
                        or finding.status in output_options.status
                    ):
                        input_compliance_frameworks = list(
                            set(output_options.output_modes).intersection(
                                available_compliance_frameworks
                            )
                        )
                        fill_compliance(
                            output_options,
                            finding,
                            provider,
                            file_descriptors,
                            input_compliance_frameworks,
                        )

                        add_manual_controls(
                            output_options,
                            provider,
                            file_descriptors,
                            input_compliance_frameworks,
                        )

                        # AWS specific outputs
                        if finding.check_metadata.Provider == "aws":
                            if "json-asff" in file_descriptors:
                                # Initialize this field using the class within fill_json_asff not here
                                json_asff_finding = fill_json_asff(provider, finding)

                                json.dump(
                                    json_asff_finding.dict(exclude_none=True),
                                    file_descriptors["json-asff"],
                                    indent=4,
                                )
                                file_descriptors["json-asff"].write(",")

                        # Common Output Data
                        provider_data_mapping = get_provider_data_mapping(provider)
                        common_finding_data = fill_common_finding_data(
                            finding, output_options.unix_timestamp
                        )
                        csv_data = {}
                        csv_data.update(provider_data_mapping)
                        csv_data.update(common_finding_data)
                        csv_data["compliance"] = get_check_compliance(
                            finding, provider.type, output_options
                        )
                        finding_output = generate_provider_output(
                            provider, finding, csv_data
                        )
                        # JSON
                        if "json-ocsf" in file_descriptors:
                            detection_finding = fill_json_ocsf(finding_output)
                            # print(file)
                            file_descriptors["json-ocsf"].write(
                                detection_finding.json(exclude_none=True, indent=4)
                            )
                            file_descriptors["json-ocsf"].write(",")

                        if "html" in file_descriptors:
                            fill_html(file_descriptors["html"], finding_output)

                        # CSV
                        if "csv" in file_descriptors:
                            finding_output.compliance = unroll_dict(
                                finding_output.compliance
                            )
                            finding_output.account_tags = unroll_list(
                                finding_output.account_tags, ","
                            )
                            csv_writer = DictWriter(
                                file_descriptors["csv"],
                                fieldnames=generate_csv_fields(FindingOutput),
                                delimiter=";",
                            )

                            csv_writer.writerow(finding_output.dict())

        else:  # No service resources in the whole account
            color = set_report_color("MANUAL")
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


def set_report_color(status: str, muted: bool = False) -> str:
    """Return the color for a give result status"""
    color = ""
    if muted:
        color = orange_color
    elif status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "MANUAL":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL or MANUAL.")
    return color


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
    all_fails_are_muted = True

    for finding in findings:
        # Save the resource_id
        resources.add(finding.resource_id)
        if finding.status == "PASS":
            total_pass += 1
            findings_count += 1
        if finding.status == "FAIL":
            total_fail += 1
            findings_count += 1
            if not finding.muted and all_fails_are_muted:
                all_fails_are_muted = False

    stats["total_pass"] = total_pass
    stats["total_fail"] = total_fail
    stats["resources_count"] = len(resources)
    stats["findings_count"] = findings_count
    stats["all_fails_are_muted"] = all_fails_are_muted

    return stats
