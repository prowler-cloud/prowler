from csv import DictWriter

from colorama import Fore, Style

from config.config import csv_header, timestamp
from lib.outputs.models import Check_Output
from lib.utils.utils import file_exists, open_file


def report(check_findings, output_options, audit_info):
    check_findings.sort(key=lambda x: x.region)
    format_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
    # check output options
    file_descriptors = {}
    for output_mode in output_options.output_modes:
        if output_mode == "csv":
            filename = (
                f"prowler-output-{audit_info.audited_account}-{format_timestamp}.csv"
            )
            if file_exists(filename):
                file_descriptor = open_file(
                    f"prowler-output-{audit_info.audited_account}-{format_timestamp}.csv",
                    "a",
                )
            else:
                file_descriptor = open_file(
                    f"prowler-output-{audit_info.audited_account}-{format_timestamp}.csv",
                    "a",
                )
                # csv_writer = writer(file_descriptor, delimiter=';')
                # csv_writer.writerow(csv_header)
                csv_writer = DictWriter(
                    file_descriptor, fieldnames=csv_header, delimiter=";"
                )
                csv_writer.writeheader()

            file_descriptors.update({output_mode: file_descriptor})

    for finding in check_findings:
        # printing the finding ...
        finding_output = Check_Output(
            audit_info.audited_account, audit_info.profile, finding
        )
        color = set_report_color(finding.status)
        if output_options.is_quiet and "FAIL" in finding.status:
            print(
                f"{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.result_extended}"
            )
        elif not output_options.is_quiet:
            print(
                f"{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.result_extended}"
            )
        # sending the finding to input options
        if "csv" in file_descriptors:
            csv_writer = DictWriter(
                file_descriptor, fieldnames=csv_header, delimiter=";"
            )
            # csv_line = [audit_info.profile,audit_info.audited_account,finding.region,finding.check_metadata.CheckID,finding.status,finding.check_metadata.CheckTitle,finding.result_extended]
            csv_writer.writerow(finding_output.__dict__)

    # Close all file descriptors
    for file_descriptor in file_descriptors:
        file_descriptors.get(file_descriptor).close()


def set_report_color(status):
    color = ""
    if status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "ERROR":
        color = Fore.BLACK
    elif status == "WARNING":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL, ERROR or WARNING")
    return color
