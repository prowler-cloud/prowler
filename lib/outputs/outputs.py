from csv import DictWriter

from colorama import Fore, Style

from config.config import csv_extension, timestamp
from lib.outputs.models import Check_Output
from lib.utils.utils import file_exists, open_file


def report(check_findings, output_options, audit_info, organizations_info):
    check_findings.sort(key=lambda x: x.region)

    # check output options
    file_descriptors = fill_file_descriptors(
        output_options.output_modes, audit_info.audited_account
    )

    for finding in check_findings:
        # printing the finding ...
        finding_output = Check_Output(
            audit_info.audited_account, audit_info.profile, finding, organizations_info
        )
        color = set_report_color(finding.status)
        if output_options.is_quiet and "FAIL" in finding.status:
            print(
                f"{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.status_extended}"
            )
        elif not output_options.is_quiet:
            print(
                f"{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.status_extended}"
            )
        # sending the finding to input options
        if "csv" in file_descriptors:

            csv_writer = DictWriter(
                file_descriptors["csv"], fieldnames=generate_csv_fields(), delimiter=";"
            )
            # csv_line = [audit_info.profile,audit_info.audited_account,finding.region,finding.check_metadata.CheckID,finding.status,finding.check_metadata.CheckTitle,finding.result_extended]
            csv_writer.writerow(finding_output.__dict__)

    # Close all file descriptors
    for file_descriptor in file_descriptors:
        file_descriptors.get(file_descriptor).close()


def fill_file_descriptors(output_modes, audited_account):
    file_descriptors = {}
    format_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
    for output_mode in output_modes:
        if output_mode == "csv":
            filename = (
                f"prowler-output-{audited_account}-{format_timestamp}{csv_extension}"
            )
            if file_exists(filename):
                file_descriptor = open_file(
                    f"prowler-output-{audited_account}-{format_timestamp}{csv_extension}",
                    "a",
                )
            else:
                file_descriptor = open_file(
                    f"prowler-output-{audited_account}-{format_timestamp}{csv_extension}",
                    "a",
                )
                # csv_writer = writer(file_descriptor, delimiter=';')
                # csv_writer.writerow(csv_header)
                csv_header = [x.upper() for x in generate_csv_fields()]
                csv_writer = DictWriter(
                    file_descriptor, fieldnames=csv_header, delimiter=";"
                )
                csv_writer.writeheader()

            file_descriptors.update({output_mode: file_descriptor})
    return file_descriptors


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


def generate_csv_fields():
    csv_fields = []
    for field in Check_Output.__dict__["__annotations__"].keys():
        csv_fields.append(field)
    return csv_fields
