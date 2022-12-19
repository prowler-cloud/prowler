from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.html import add_html_header
from prowler.lib.outputs.models import (
    Aws_Check_Output_CSV,
    Azure_Check_Output_CSV,
    Check_Output_CSV_CIS,
    Check_Output_CSV_ENS_RD2022,
    generate_csv_fields,
)
from prowler.lib.utils.utils import file_exists, open_file
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


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
