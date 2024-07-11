from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from prowler.config.config import csv_file_suffix
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.models import (
    Check_Output_CSV_AWS_ISO27001_2013,
    Check_Output_CSV_AWS_Well_Architected,
    Check_Output_CSV_ENS_RD2022,
    Check_Output_CSV_Generic_Compliance,
)
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.output import Finding
from prowler.lib.utils.utils import file_exists, open_file


def initialize_file_descriptor(
    filename: str,
    format: Any = Finding,
) -> TextIOWrapper:
    """Open/Create the output file. If needed include headers or the required format, by default will use the FindingOutput"""
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
            # Format is the class model of the CSV format to print the headers
            csv_header = [x.upper() for x in generate_csv_fields(format)]
            csv_writer = DictWriter(
                file_descriptor, fieldnames=csv_header, delimiter=";"
            )
            csv_writer.writeheader()
        return file_descriptor
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def fill_file_descriptors(output_modes, output_directory, output_filename, provider):
    try:
        file_descriptors = {}
        if output_modes:
            for output_mode in output_modes:
                # FIXME: Remove this once we always use the new CSV(Output)
                if output_mode == "csv":
                    continue
                elif output_mode == "json-ocsf":
                    continue
                elif output_mode == "json-asff":
                    continue
                elif output_mode == "html":
                    continue
                # FIXME: Remove this once we merge all the compliance frameworks
                if "cis_" in output_mode:
                    continue
                elif "mitre_attack_" in output_mode:
                    continue

                elif provider.type == "gcp":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename,
                        Check_Output_CSV_Generic_Compliance,
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "kubernetes":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename,
                        Check_Output_CSV_Generic_Compliance,
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "azure":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename,
                        Check_Output_CSV_Generic_Compliance,
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "aws":
                    # Compliance frameworks
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    if output_mode == "ens_rd2022_aws":
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            Check_Output_CSV_ENS_RD2022,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    elif "aws_well_architected_framework" in output_mode:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            Check_Output_CSV_AWS_Well_Architected,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    elif output_mode == "iso27001_2013_aws":
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            Check_Output_CSV_AWS_ISO27001_2013,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    else:
                        # Generic Compliance framework
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            Check_Output_CSV_Generic_Compliance,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptors
