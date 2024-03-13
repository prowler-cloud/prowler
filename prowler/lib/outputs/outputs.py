import json
from csv import DictWriter

from colorama import Fore, Style

from prowler.config.config import available_compliance_frameworks, orange_color
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.compliance import (
    add_manual_controls,
    fill_compliance,
)
from prowler.lib.outputs.csv.csv import (
    fill_common_data_csv,
    generate_csv_fields,
    generate_provider_output_csv,
    get_provider_data_mapping,
)
from prowler.lib.outputs.csv.models import CSVRow
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.json import fill_json_asff, fill_json_ocsf
from prowler.lib.outputs.models import (
    Check_Output_JSON_ASFF,
    get_check_compliance,
    unroll_dict,
)


def stdout_report(finding, color, verbose, status):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.check_metadata.ServiceName
    if finding.check_metadata.Provider == "gcp":
        details = finding.location.lower()
    if finding.check_metadata.Provider == "kubernetes":
        details = finding.namespace.lower()

    if verbose and (not status or finding.status in status):
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
            if output_options.output_modes:
                # We have to create the required output files
                file_descriptors = fill_file_descriptors(
                    output_options.output_modes,
                    output_options.output_directory,
                    output_options.output_filename,
                    provider,
                )

            for finding in check_findings:
                # Print findings by stdout
                color = set_report_color(finding.status)
                stdout_report(
                    finding, color, output_options.verbose, output_options.status
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
                                finding_output = Check_Output_JSON_ASFF()
                                fill_json_asff(
                                    finding_output, provider, finding, output_options
                                )

                                json.dump(
                                    finding_output.dict(exclude_none=True),
                                    file_descriptors["json-asff"],
                                    indent=4,
                                )
                                file_descriptors["json-asff"].write(",")

                        # CSV
                        if "csv" in file_descriptors:
                            provider_data = get_provider_data_mapping(provider)
                            common_data = fill_common_data_csv(
                                finding, output_options.unix_timestamp
                            )
                            compliance_data = unroll_dict(
                                get_check_compliance(
                                    finding, provider.type, output_options
                                )
                            )
                            csv_data = {}
                            csv_data.update(provider_data)
                            csv_data.update(common_data)
                            csv_data["compliance"] = compliance_data

                            csv_writer = DictWriter(
                                file_descriptors["csv"],
                                fieldnames=generate_csv_fields(CSVRow),
                                delimiter=";",
                            )

                            finding_output = generate_provider_output_csv(
                                provider, finding, csv_data
                            )

                            csv_writer.writerow(finding_output.dict())

                        if "json-ocsf" in file_descriptors:
                            finding_output = fill_json_ocsf(
                                provider, finding, output_options
                            )

                            json.dump(
                                finding_output.dict(),
                                file_descriptors["json-ocsf"],
                                indent=4,
                                default=str,
                            )
                            file_descriptors["json-ocsf"].write(",")

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


def set_report_color(status: str) -> str:
    """Return the color for a give result status"""
    color = ""
    if status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "ERROR":
        color = Fore.BLACK
    elif status == "MUTED":
        color = orange_color
    elif status == "MANUAL":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL, ERROR or MUTED")
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
